defmodule RakNet.Server do
  @moduledoc """
  A server implementing the RakNet protocol
  """
  require Logger
  import XUtil.Time, only: [unix_timestamp_ms: 0]

  defmodule Spawner do
    @moduledoc "A dumb wrapper to make a spawned function supervisable"
    def start_link(impl_fn), do: {:ok, spawn(impl_fn)}
  end

  def child_spec([receiver | [port | options]]) do
    %{
      # String.to_atom/1 is fine here, because we'll be creating a very limited number of listeners per port
      # credo:disable-for-next-line
      id: String.to_atom("#{__MODULE__}:#{port}"),
      start: {__MODULE__, :start_link, [receiver, port, options]},
      restart: :permanent,
      type: :worker
    }
  end

  def start_link(client_module, port, options \\ []) when is_atom(client_module) and is_integer(port) do
    defaults = [
      custom_packets: [],
      custom_types: [],
      client_data: %{},
      client_timeout_ms: 10_000,
      # Corresponds to #define INCLUDE_TIMESTAMP_WITH_DATAGRAMS
      # (which is in turn enabled by USE_SLIDING_WINDOW_CONGESTION_CONTROL in the RakNetDefinesOverrides.h)
      include_timestamp_with_datagrams: false,
      # Corresponds to #define MAXIMUM_NUMBER_OF_INTERNAL_IDS
      max_number_of_internal_ids: 10,
      open_ipv4_socket: true,
      open_ipv6_socket: System.get_env("SEPARATE_IPV6_PORT") != "false",
      # TODO: use gen_udp directly and reopen the socket if it gets closed
      send: &Socket.Datagram.send!/3,
      server_identifier: make_unique_id(),
      offline_ping_response: "RakNet Server"
    ]

    host = Keyword.get(options, :host, {0, 0, 0, 0})

    config =
      defaults
      |> Keyword.merge(options)
      |> Enum.into(%{
        client_module: struct(client_module),
        encoded_host: RakNet.SystemAddress.encode(%{address: host, port: port})
      })

    socket_v4 = if config[:open_ipv4_socket], do: elem(open_socket(4, port), 1), else: nil
    socket_v6 = if config[:open_ipv6_socket], do: elem(open_socket(6, port), 1), else: nil
    sockets = {socket_v4, socket_v6}

    Supervisor.start_link(
      [
        # String.to_atom/1 is fine here, because we'll be creating a very limited number of listeners per port
        # credo:disable-for-lines:2
        %{id: String.to_atom("#{__MODULE__}:#{port}_ipv4"), start: {Spawner, :start_link, [fn -> serve_v4(sockets, config) end]}},
        %{id: String.to_atom("#{__MODULE__}:#{port}_ipv6"), start: {Spawner, :start_link, [fn -> serve_v6(sockets, config) end]}}
      ],
      strategy: :one_for_one
    )
  end

  defp open_socket(ip_version, port) when ip_version == 4 or ip_version == 6 do
    addl_args = if ip_version == 4, do: [:inet], else: [:inet6, {:ipv6_v6only, true}]
    :gen_udp.open(port, [:binary, {:active, false}] ++ addl_args)
  end

  @doc "The current Unix timestamp, in milliseconds"
  def timestamp(offset \\ 0), do: unix_timestamp_ms() - offset

  @doc "A 64-bit unique ID"
  def make_unique_id, do: <<timestamp()::size(48), :rand.uniform(65_536)::size(16)>>

  defp serve_v4({nil, _}, _config), do: :ok
  defp serve_v4({socket_v4, _} = sockets, config), do: serve_impl(&serve_v4/2, socket_v4, sockets, config)
  defp serve_v6({_, nil}, _config), do: :ok
  defp serve_v6({_, socket_v6} = sockets, config), do: serve_impl(&serve_v6/2, socket_v6, sockets, config)

  defp serve_impl(server, receive_socket, sockets, config) do
    # We have to do basic decoding in the main process, because it may update our client connection state. :(
    case Socket.Datagram.recv!(receive_socket) do
      nil ->
        server.(sockets, config)

      {packet, {client_ip, client_port}} = received_raw ->
        case decode(received_raw, sockets, config) do
          # Send to a client process to parse & optionally respond (never do any work here, since this is a single process)
          {:connected, {client, packet_type, data}} -> RakNet.Connection.handle_message(client, packet_type, data)
          {:unconnected, decoded} -> spawn(fn -> handle_unconnected_packet(sockets, config, decoded) end)
          _ -> Logger.error("Failed to decode packet from #{inspect(client_ip)}:#{client_port}\nPacket: #{inspect(packet)}")
        end
    end

    server.(sockets, config)
  end

  # One of:
  #   {:error, %{}}
  #   {:unconnected, {client_ip_and_port, :unconnected_ping, data}}
  #   {:connected, {client, packet_type, data}}
  defp decode({packet, client_ip_and_port}, sockets, config) do
    case packet_decode(packet, config) do
      {:error, _msg} = err ->
        err

      {:ok, :open_connection_request_1, data} ->
        {:connected, {open_connection(sockets, client_ip_and_port, config), :open_connection_request_1, data}}

      {:ok, :unconnected_ping, data} ->
        {:unconnected, {client_ip_and_port, :unconnected_ping, data}}

      {:ok, :unconnected_ping_open_connections, data} ->
        {:unconnected, {client_ip_and_port, :unconnected_ping_open_connections, data}}

      {:ok, packet_type, data} ->
        case lookup(client_ip_and_port) do
          nil -> {:unconnected, {client_ip_and_port, packet_type, data}}
          client -> {:connected, {client, packet_type, data}}
        end
    end
  end

  defp open_connection(sockets, {host, port} = client_ip_and_port, config) do
    existing_client = lookup(client_ip_and_port)

    # TODO: Nuke the existing client, create a new one
    if existing_client do
      Logger.debug("Existing client requested to open a new connection")
      RakNet.Connection.stop(existing_client)
    else
      Logger.debug("Open a new connection to #{inspect(host)}:#{port}")
    end

    {:ok, new_client} =
      RakNet.Connection.start_link(%RakNet.Connection.State{
        host: host,
        port: port,
        encoded_host: config[:encoded_host],
        client_ips_and_ports: [client_ip_and_port],
        encoded_client: RakNet.SystemAddress.encode(%{address: host, port: port}),
        timeout_ms: config[:client_timeout_ms],
        base_time: timestamp(),
        server_identifier: config[:server_identifier],
        client_module: config[:client_module],
        client_data: config[:client_data],
        include_timestamp_with_datagrams: config[:include_timestamp_with_datagrams],
        max_number_of_internal_ids: config[:max_number_of_internal_ids],
        respond: make_responder(sockets, config)
      })

    # Do *not* bring down the whole server if the connection dies; if that happens,
    # we'll just start a new proceses next time we hear from the user.
    Process.unlink(new_client)
    Registry.register(RakNet.Connection, client_ip_and_port, new_client)
    new_client
  end

  defp lookup(client_ip_and_port) do
    case Registry.lookup(RakNet.Connection, client_ip_and_port) do
      [{_, client}] ->
        if Process.alive?(client) do
          client
        else
          Registry.unregister(RakNet.Connection, client_ip_and_port)
          nil
        end

      _ ->
        nil
    end
  end

  defp packet_decode(<<identifier::unsigned-size(8), data::binary>>, _config) do
    case RakNet.Message.name(identifier) do
      :error -> {:error, "Unknown packet identifier"}
      name -> {:ok, name, data}
    end
  end

  defp handle_unconnected_packet(sockets, config, {client_ip_port, :unconnected_ping, <<ping_time::size(64), _::binary>>}) do
    send_unconnected_pong(sockets, client_ip_port, ping_time, config)
  end

  defp handle_unconnected_packet(sockets, config, {client_ip_port, :unconnected_ping_open_connections, <<ping_time::size(64), _::binary>>}) do
    send_unconnected_pong(sockets, client_ip_port, ping_time, config)
  end

  defp handle_unconnected_packet(sockets, config, {client_ip_port, _other, _data}) do
    send(sockets, <<RakNet.Message.binary(:connection_lost)>>, client_ip_port, config)
  end

  defp send_unconnected_pong(sockets, client_ip_port, ping_time, config) do
    send(
      sockets,
      <<RakNet.Message.binary(:unconnected_pong), ping_time::size(64), config[:server_identifier]::binary,
        RakNet.Message.offline_msg_id()::binary>>,
      client_ip_port,
      config
    )
  end

  defp make_responder(sockets, config) do
    fn packet, ip_and_port ->
      send(sockets, packet, ip_and_port, config)
    end
  end

  defp send(sockets, packet, client_ip_and_port, config) do
    sockets
    |> choose_socket(client_ip_and_port)
    |> config[:send].(packet, client_ip_and_port)
  end

  defp choose_socket({socket_v4, socket_v6}, client_ip_and_port) do
    case RakNet.SystemAddress.ip_version(client_ip_and_port) do
      4 -> socket_v4
      6 -> socket_v6
    end
  end
end
