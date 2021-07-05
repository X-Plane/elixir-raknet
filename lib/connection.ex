defprotocol RakNet.Client do
  def new(client_struct, connection_pid, module_data)
  def receive(client, packet_type, packet_buffer, time_comp)
  def got_ack(client, send_receipt_id)
  def disconnect(client)
end

defmodule RakNet.Connection do
  @moduledoc "A stateful connection to a client"
  use GenServer, restart: :transient
  require Logger
  alias RakNet.Message
  alias RakNet.ReliabilityLayer
  alias RakNet.ReliabilityLayer.Reliability
  import XUtil.Map
  import XUtil.Time, only: [unix_timestamp_ms: 0]

  defmodule State do
    @moduledoc "The state we pass around within a RakNet.Connection GenServer"
    @enforce_keys [
      :host,
      :port,
      :encoded_host,
      :client_ips_and_ports,
      :encoded_client,
      :server_identifier,
      :client_module,
      :respond,
      :base_time
    ]
    defstruct host: nil,
              port: nil,
              encoded_host: <<>>,
              # IPs may be 4 ipv4 octets, or 8 ipv6 hextets
              client_ips_and_ports: [],
              encoded_client: <<>>,
              server_identifier: <<>>,
              # The RakNet.Client module that implements your game logic client; this receives game-specific packets and
              # uses the respond function we give it to communicate back to the user.
              client_module: nil,
              # Data you've asked us to pass to your client_module's new/2 factory
              client_data: %{},
              # The means the RakNet.Server that created us gave us to send a message across the wire to the client
              respond: nil,
              # The :os.system_time(:millisecond) time at which we were created.
              # Use this to get RakNet.Server.timestamp() values relative to creation time
              base_time: 0,
              # Milliseconds of inactivity before we time out this connection and cause it to self-destruct.
              # We count as "activity" a) connected pongs, and b) encapsulated client data packets
              # (but not RakNet protocol overhead, like conneciton handshakes)
              timeout_ms: 30_000,
              # Corresponds to #define INCLUDE_TIMESTAMP_WITH_DATAGRAMS
              # (which is in turn enabled by USE_SLIDING_WINDOW_CONGESTION_CONTROL in the RakNetDefinesOverrides.h)
              include_timestamp_with_datagrams: false,
              # Corresponds to #define MAXIMUM_NUMBER_OF_INTERNAL_IDS
              max_number_of_internal_ids: 10,

              # Server doesn't need to set any of this
              receive_sequence: nil,
              # Sequencing for whole messages
              send_sequence: 0,
              message_index: 0,
              ordered_write_index: 0,
              # Maps send_sequence indices to lists of (reliable only?) packets
              unacknowledged_sent: %{},
              # Sequencing for sequenced-but-not-ordered messages
              sequenced_packet: 0,
              packet_buffer: [],
              ack_buffer: [],
              mtu_size: 0,
              # The :os.system_time(:millisecond) time at which we enqueued the oldest unset acknowledgement packet
              oldest_unsent_ack_time_ms: 0,
              # Last diff between our timestamp we sent with a ping and the time we received the pong
              last_rtts: [],
              # A TRef to the timer that will time out this connection and cause it to self-destruct
              timeout_ref: nil,
              # The instance of business_logic_module that tracks the state for this connection
              client: nil
  end

  defmodule Resendable do
    @moduledoc "A set of packets that we'll resend if we don't get an :ack"
    @enforce_keys [:packets, :index, :next_resend_time]
    defstruct packets: [], index: 0, next_resend_time: 0
  end

  @udp_header_size 28

  # Sync rate is hardcoded to 1/100 sec in RakNet
  @sync_ms 10
  @ping_ms 5000

  # This is hard-coded in RakNet, to prevent you from using all your RAM on a single client that fails to respond to
  # a big stream of reliable packets
  @max_tracked_reliable_packets 512

  # RakNet calculated RTO dynamically based on round trip time variance and the like... we're just gonna make it 1 second + rtt
  @retransmition_time_out_ms 1000

  # RakNet calculates round-trip time (RTT) as the average of your up-to-5 last ping times
  @rtt_window_size 5

  def start_link(%State{} = state) do
    GenServer.start_link(__MODULE__, state)
  end

  def stop(connection_pid), do: GenServer.stop(connection_pid, :shutdown)

  def handle_message(connection_pid, message_type, data) do
    GenServer.cast(connection_pid, {message_type, data})
  end

  @doc """
  Returns one of:
  {:ok, nil}  (if you didn't request an ack receipt)
  {:ok, ack_receipt_id}
  {:error, message}
  """
  def send(connection_pid, reliability, message)

  def send(connection_pid, reliability, message)
      when is_bitstring(message) and reliability in [:unreliable_ack_receipt, :reliable_ack_receipt, :reliable_ordered_ack_receipt] do
    {:ok, GenServer.call(connection_pid, {:send, reliability, message})}
  end

  def send(connection_pid, reliability, message) when is_bitstring(message) and is_atom(reliability) do
    GenServer.cast(connection_pid, {:send, reliability, message})
    {:ok, nil}
  end

  ################ Server Implementation ################
  @impl GenServer
  def init(state) do
    {:ok, _} = :timer.send_interval(@sync_ms, :sync)
    Process.flag(:trap_exit, true)
    {:ok, reschedule_timeout(state)}
  end

  @raknet_protocol_version 6
  @use_security 0

  @impl GenServer
  def handle_info(:sync, connection) do
    # TODO: Variable retransmission timeout based on RTT: send if estimatedTimeToNextTick+curTime < oldestUnsentAck+rto-RTT
    {:noreply,
     connection
     |> sync_ack_buffer()
     |> sync_requeue_reliable_data_packets()
     |> sync_enqueued_data_packets()}
  end

  @impl GenServer
  def handle_info(:sync_ping, connection) do
    {:noreply, ping(connection)}
  end

  @impl GenServer
  def handle_info({:EXIT, _pid, reason}, connection) do
    Logger.debug("Connection exiting due to reason #{inspect(reason)}")

    if not is_nil(connection.client) do
      RakNet.Client.disconnect(connection.client)
    end

    Process.exit(self(), :kill)
  end

  defp sync_ack_buffer(connection) do
    current_time = unix_timestamp_ms()

    if connection.oldest_unsent_ack_time_ms > 0 and
         (connection.oldest_unsent_ack_time_ms <= current_time - @sync_ms or length(connection.ack_buffer) > 20) do
      ack(sweep_line(connection.ack_buffer), connection.respond, connection)
      %{connection | ack_buffer: [], oldest_unsent_ack_time_ms: 0}
    else
      connection
    end
  end

  defp sync_enqueued_data_packets(connection) do
    if Enum.empty?(connection.packet_buffer) do
      connection
    else
      updated_conn = send_immediate(connection.packet_buffer, connection)
      %{updated_conn | packet_buffer: []}
    end
  end

  defp sync_requeue_reliable_data_packets(connection) do
    current_time = RakNet.Server.timestamp()

    # PerfTODO: This is more expensive than it needs to be... Instead use a queue of {resend_time, packet}?
    to_resend =
      Map.values(connection.unacknowledged_sent)
      |> Enum.sort_by(select_key(:next_resend_time))
      |> Enum.take_while(fn resendable -> resendable.next_resend_time <= current_time end)

    if Enum.empty?(to_resend) do
      connection
    else
      packets = to_resend |> Enum.map(select_key(:packets)) |> List.flatten()
      # When the packets actually go out, we'll re-add them to unacknowledged_sent queue (with a new index)
      indices = Enum.map(to_resend, select_key(:index))

      %{
        connection
        | packet_buffer: packets ++ connection.packet_buffer,
          unacknowledged_sent: Map.drop(connection.unacknowledged_sent, indices)
      }
    end
  end

  defp ping(connection) do
    enqueue(:unreliable, make_ping_buffer(connection.base_time), connection)
  end

  defp send_immediate(packets, connection) when is_list(packets) do
    encoded =
      RakNet.Packet.encode(%{
        sequence_number: connection.send_sequence,
        encapsulated_packets: connection.packet_buffer,
        timestamp: if(connection.include_timestamp_with_datagrams, do: RakNet.Server.timestamp(connection.base_time), else: -1)
      })

    # TODO: Periodically retransmit unacknowledged reliable packets
    # TODO: Split packets larger than connection.mtu_size
    # credo:disable-for-next-line
    connection.respond.(<<Message.binary(:data_packet_4), encoded::binary>>, List.first(connection.client_ips_and_ports))

    {reliable_packets, _} = Enum.split_with(packets, fn %ReliabilityLayer.Packet{reliability: r} -> Reliability.is_reliable?(r) end)

    updated_unacknowledged =
      if Enum.empty?(reliable_packets) or map_size(connection.unacknowledged_sent) > @max_tracked_reliable_packets do
        connection.unacknowledged_sent
      else
        Map.put(connection.unacknowledged_sent, connection.send_sequence, %Resendable{
          index: connection.send_sequence,
          packets: reliable_packets,
          next_resend_time: RakNet.Server.timestamp() + rtt(connection) * 1.5 + @retransmition_time_out_ms
        })
      end

    %{
      connection
      | unacknowledged_sent: updated_unacknowledged,
        ordered_write_index: 1 + max(connection.ordered_write_index, max_packet_value(reliable_packets, :order_index)),
        message_index: 1 + max(connection.message_index, max_packet_value(reliable_packets, :message_index)),
        send_sequence: connection.send_sequence + 1
    }
  end

  defp max_packet_value(packets, packet_key, default \\ -1) when is_list(packets) and is_atom(packet_key) do
    case Enum.max_by(packets, select_key(packet_key), fn -> default end) do
      %ReliabilityLayer.Packet{} = p ->
        case Map.fetch!(p, packet_key) do
          num when is_number(num) -> num
          _ -> default
        end

      _ ->
        default
    end
  end

  @impl GenServer
  def handle_cast({:open_connection_request_1, data}, connection) do
    Logger.debug("Received open connection request 1 from #{inspect(List.first(connection.client_ips_and_ports))}")
    <<_offline_msg_id::binary-size(16), @raknet_protocol_version::size(8), _zero_pad_to_mtu_size::bitstring>> = data
    # +1 for the message ID byte (:open_connection_request_1)
    mtu_size = byte_size(data) + @udp_header_size + 1

    message =
      <<Message.binary(:open_connection_reply_1), Message.offline_msg_id()::binary, connection.server_identifier::binary,
        @use_security::size(8), mtu_size::size(16)>>

    # credo:disable-for-next-line
    connection.respond.(message, List.first(connection.client_ips_and_ports))
    Logger.debug("Sent open connection reply 1 to #{inspect(List.first(connection.client_ips_and_ports))}")

    {:noreply, %{connection | mtu_size: mtu_size}}
  rescue
    err ->
      Logger.error("Failed to parse open connection request 1 of #{byte_size(data)} bytes (needed at least 24 bytes)")
      Logger.error("Packet was: #{inspect(data)}")
      Logger.error("Connection state was: #{inspect(connection)}")
      reraise(err, __STACKTRACE__)
  end

  @impl GenServer
  def handle_cast({:open_connection_request_2, data}, connection) do
    Logger.debug("Received open connection request 2 from #{inspect(List.first(connection.client_ips_and_ports))}")

    server_addr_bytes = byte_size(data) - 16 - 2 - 8
    <<_offline_id::binary-size(16), _svr_address::binary-size(server_addr_bytes), mtu_size::size(16), _client_id::size(64)>> = data

    connection.respond.(
      <<Message.binary(:open_connection_reply_2), Message.offline_msg_id()::binary, connection.server_identifier::binary,
        connection.encoded_client::binary, mtu_size::size(16), @use_security::size(8)>>,
      # credo:disable-for-next-line
      List.first(connection.client_ips_and_ports)
    )

    Logger.debug("Sent open connection reply 2 to #{inspect(List.first(connection.client_ips_and_ports))}")
    {:noreply, connection}
  end

  @impl GenServer
  def handle_cast({:ping, <<ping_time::size(64)>>}, connection) do
    {:noreply, enqueue(:unreliable, make_pong_buffer(ping_time, connection.base_time), reschedule_timeout(connection))}
  end

  @impl GenServer
  def handle_cast({:pong, <<our_sent_time::size(64), _::binary>>}, %State{last_rtts: prev_rtts} = connection) do
    ping_time = RakNet.Server.timestamp(connection.base_time) - our_sent_time
    updated_rtts = [ping_time | Enum.take(prev_rtts, @rtt_window_size - 1)]
    {:noreply, reschedule_timeout(%{connection | last_rtts: updated_rtts})}
  end

  @impl GenServer
  def handle_cast({:ack, packet}, %State{unacknowledged_sent: unacked} = connection) do
    timestamp_size = if connection.include_timestamp_with_datagrams, do: 32, else: 0
    # TODO: Do something with the timestamp if > 0
    <<_timestamp::size(timestamp_size), ack_portion::binary>> = packet
    {removed, still_unacked} = Map.split(unacked, message_indices_from_ack(ack_portion))

    msgs_received =
      removed
      |> Map.values()
      # Values from the removed map are Resendable structs; we just need to inspect the packets
      |> Enum.flat_map(select_key(:packets))
      |> Enum.filter(fn %ReliabilityLayer.Packet{reliability: r} -> Reliability.needs_client_ack?(r) end)
      |> Enum.map(select_key(:message_index))
      |> MapSet.new()

    Enum.each(msgs_received, fn msg_idx -> RakNet.Client.got_ack(connection.client, msg_idx) end)

    {:noreply, %{connection | unacknowledged_sent: still_unacked}}
  end

  @impl GenServer
  def handle_cast({:nack, _packet}, connection) do
    # TODO: Resend?
    {:noreply, connection}
  end

  @impl GenServer
  def handle_cast({:client_connect, data}, connection) do
    Logger.debug("Received client connect from #{inspect(List.first(connection.client_ips_and_ports))}")
    <<_client_id::size(64), time_sent::size(64), @use_security::size(8), _password::binary>> = data

    send_pong = RakNet.Server.timestamp(connection.base_time)

    # TODO: Support IPv6
    # TODO: Should we offer other ports clients can connect on?
    empty_ip =
      RakNet.SystemAddress.encode(%{
        version: 4,
        address: {255, 255, 255, 255},
        port: 0
      })

    packet =
      <<Message.binary(:server_handshake), connection.encoded_client::binary, 0::size(16)>> <>
        :erlang.list_to_binary([connection.encoded_host] ++ List.duplicate(empty_ip, 9)) <>
        <<time_sent::size(64), send_pong::size(64)>>

    Logger.debug("Sent server handshake to #{inspect(List.first(connection.client_ips_and_ports))}")
    {:noreply, enqueue(:reliable_ordered, packet, connection)}
  end

  @impl GenServer
  def handle_cast({:client_handshake, data}, connection) do
    Logger.debug("Received client handshake from #{inspect(List.first(connection.client_ips_and_ports))}")
    # A system address is: 1 byte v4 or v6, followed by EITHER 4 bytes v4 address + 2 bytes port OR 28 bytes v6 addr & port
    addresses_length = bit_size(data) - 2 * 64
    <<_addresses::bitstring-size(addresses_length), ping_time::size(64), pong_time::size(64)>> = data

    # We send the first ping immediately, then subsequent pings every 5 seconds
    updated_conn =
      enqueue(
        :unreliable,
        [
          make_ping_buffer(connection.base_time),
          make_pong_buffer(ping_time, connection.base_time)
        ],
        connection
      )

    {:ok, _} = :timer.send_interval(@ping_ms, :sync_ping)
    rtt = max(0, pong_time - RakNet.Server.timestamp(connection.base_time))
    client = RakNet.Client.new(connection.client_module, self(), connection.client_data)
    Logger.debug("Finalized connection handshake with #{inspect(List.first(connection.client_ips_and_ports))}")
    {:noreply, %{updated_conn | last_rtts: [rtt], client: client}}
  end

  @impl GenServer
  def handle_cast({:client_disconnect, _data}, connection) do
    Logger.debug("Client #{inspect(List.first(connection.client_ips_and_ports))} disconnected")

    if not is_nil(connection.client) do
      RakNet.Client.disconnect(connection.client)
    end

    Process.exit(self(), :normal)
    {:noreply, connection}
  end

  @impl GenServer
  def handle_cast({packet_type, data}, %State{} = connection) when is_atom(packet_type) do
    %{encapsulated_packets: encapsulated_packets, sequence_number: recv_sequence, timestamp: _timestamp} =
      if connection.include_timestamp_with_datagrams do
        RakNet.Packet.decode_with_timestamp(data)
      else
        RakNet.Packet.decode_no_timestamp(data)
      end

    if Enum.empty?(encapsulated_packets) do
      # Had a parsing error!
      Logger.error("Failed to parse #{packet_type} (#{byte_size(data) + 1} bytes) #{inspect(data, limit: :infinity)}")
      {:noreply, connection}
    else
      {:noreply,
       encapsulated_packets
       |> Enum.reduce({connection, :unacknowledged}, fn packet, {conn, acked} ->
         <<identifier::size(8), head_data::binary>> = packet.buffer
         ident_atom = Message.name(identifier)

         is_connection_negotiation = ident_atom in [:ping, :pong, :client_connect, :client_handshake, :client_disconnect]
         finished_connection_negotiation = not Enum.empty?(conn.last_rtts) and conn.client != nil

         if is_connection_negotiation or finished_connection_negotiation do
           # TODO: Sequence indices are per-channel
           # TODO: Immediately send acks for split packets
           updated_conn =
             if acked == :unacknowledged do
               %{buffer_ack(recv_sequence, conn) | receive_sequence: max(conn.receive_sequence, recv_sequence)}
             else
               conn
             end

           if is_connection_negotiation do
             {elem(handle_cast({ident_atom, head_data}, updated_conn), 1), :acknowledged}
           else
             # TODO: Support custom packet type atoms (right now we're passing through the integer values as the identifier)
             RakNet.Client.receive(updated_conn.client, identifier, head_data, rtt(updated_conn) / 2)
             {reschedule_timeout(updated_conn), :acknowledged}
           end
         else
           Logger.info("Connection to #{inspect(conn.host)}:#{conn.port} received data before connection negotiation finished")

           # credo:disable-for-next-line
           conn.respond.(<<RakNet.Message.binary(:connection_lost)>>, List.first(conn.client_ips_and_ports))
           {conn, acked}
         end
       end)
       |> elem(0)}
    end
  end

  @impl GenServer
  def handle_cast({:send, reliability, message}, %State{} = connection) do
    {:noreply, sync_enqueued_data_packets(enqueue(reliability, message, connection))}
  end

  @impl GenServer
  def handle_call({:send, reliability, message}, _from, %State{} = connection) do
    updated_conn = sync_enqueued_data_packets(enqueue(reliability, message, connection))
    {:reply, updated_conn.message_index, updated_conn}
  end

  @impl GenServer
  def terminate(reason, connection) do
    Logger.info("Terminating #{inspect(connection.host)}:#{connection.port} due to #{inspect(reason)}")
    Registry.unregister(RakNet.Connection, {connection.host, connection.port})
  end

  defp reschedule_timeout(%State{timeout_ref: nil} = connection) do
    case :timer.exit_after(connection.timeout_ms, self(), :timeout) do
      {:ok, timer_id} -> %{connection | timeout_ref: timer_id}
      _ -> connection
    end
  end

  defp reschedule_timeout(%State{} = connection) do
    case :timer.cancel(connection.timeout_ref) do
      {:ok, _} -> reschedule_timeout(%{connection | timeout_ref: nil})
      # I guess we try killing it again later?
      _ -> connection
    end
  end

  defp enqueue(reliability, buffer, connection) when is_atom(reliability) and is_bitstring(buffer) do
    enqueue(reliability, [buffer], connection)
  end

  defp enqueue(reliability, buffers, connection)
       when (reliability == :unreliable_sequenced or reliability == :reliable_sequenced or reliability == :reliable_ordered_ack_receipt) and
              is_list(buffers) do
    num_buffers = length(buffers)

    new_packets =
      buffers
      |> Enum.zip(0..(num_buffers - 1))
      |> Enum.map(fn {buffer, idx} ->
        %ReliabilityLayer.Packet{
          reliability: reliability,
          message_index: if(Reliability.is_reliable?(reliability), do: connection.message_index, else: nil),
          order_index: connection.ordered_write_index,
          sequencing_index: connection.sequenced_packet + idx,
          buffer: buffer
        }
      end)

    %{connection | packet_buffer: new_packets ++ connection.packet_buffer, sequenced_packet: connection.sequenced_packet + num_buffers}
  end

  defp enqueue(reliability, buffers, connection) when is_atom(reliability) and is_list(buffers) do
    if Reliability.valid?(reliability) do
      new_packets =
        Enum.map(buffers, fn buffer ->
          %ReliabilityLayer.Packet{
            reliability: reliability,
            message_index:
              if(Reliability.is_reliable?(reliability) or Reliability.needs_client_ack?(reliability),
                do: connection.message_index,
                else: nil
              ),
            order_index: if(Reliability.is_sequenced?(reliability), do: connection.ordered_write_index, else: nil),
            buffer: buffer
          }
        end)

      %{connection | packet_buffer: new_packets ++ connection.packet_buffer}
    else
      Logger.error("Unknown reliability atom #{reliability}")
      connection
    end
  end

  defp buffer_ack(packet_index, connection) when is_integer(packet_index) do
    case connection.ack_buffer do
      [] -> %{connection | ack_buffer: [packet_index], oldest_unsent_ack_time_ms: unix_timestamp_ms()}
      _ -> %{connection | ack_buffer: [packet_index | connection.ack_buffer]}
    end
  end

  @doc """
  The sweep line algorithm: https://en.wikipedia.org/wiki/Sweep_line_algorithm
  Given a collection of integers, it combines them into the minimum number of contiguous ranges.

      iex> RakNet.Connection.sweep_line(MapSet.new([5, 4, 3, 2, 1, 0]))
      [{0, 5}]

      iex> RakNet.Connection.sweep_line([5, 4, 3, 100, 1, 0])
      [{0, 1}, {3, 5}, {100, 100}]
  """
  def sweep_line(integers) do
    [start | sorted] = Enum.sort(integers)

    # Traverse the sorted array, while maintaining a set of "active" events:
    # whenever you see a start/end time, respectively add or drop the
    # corresponding event from the set, and add (if the active set is non-empty)
    # an event to your solution.
    sorted
    |> Enum.reduce([{start, start}], fn packet_idx, [{b, e} | rest] = acc ->
      if packet_idx == e + 1 do
        [{b, packet_idx} | rest]
      else
        [{packet_idx, packet_idx} | acc]
      end
    end)
    |> Enum.sort()
  end

  defp ack(buffered_acks, responder, connection) when is_list(buffered_acks) do
    {timestamp_bits, timestamp} =
      if connection.include_timestamp_with_datagrams do
        {32, RakNet.Server.timestamp(connection.base_time)}
      else
        {0, 0}
      end

    responder.(
      <<Message.binary(:ack), timestamp::size(timestamp_bits), length(buffered_acks)::size(16)>> <>
        :erlang.list_to_binary(
          Enum.map(buffered_acks, fn {range_min, range_max} ->
            min_is_max = if range_min == range_max, do: 1, else: 0

            <<min_is_max::size(8), range_min::little-size(24)>> <>
              if(min_is_max == 1, do: <<>>, else: <<range_max::little-size(24)>>)
          end)
        ),
      # credo:disable-for-next-line
      List.first(connection.client_ips_and_ports)
    )
  end

  def message_indices_from_ack(<<packet_count::size(16), remainder::binary>> = full) do
    parsed =
      Enum.reduce(1..packet_count, {[], remainder}, fn _, {indices_to_drop, rem_binary} ->
        case rem_binary do
          # 1 -> range min == range max (i.e., it's a single index)
          <<1::size(8), rmin::little-size(24), rem::binary>> -> {[rmin | indices_to_drop], rem}
          <<0::size(8), rmin::little-size(24), rmax::little-size(24)>> -> {Enum.to_list(rmin..rmax) ++ indices_to_drop, <<>>}
          <<0::size(8), rmin::little-size(24), rmax::little-size(24), rem::binary>> -> {Enum.to_list(rmin..rmax) ++ indices_to_drop, rem}
          _ -> :error
        end
      end)

    case parsed do
      {msg_indices_to_drop, <<>>} ->
        msg_indices_to_drop

      _ ->
        Logger.error("Ack packet failed to parse: #{inspect(full)}")
        []
    end
  end

  defp make_ping_buffer(base_time) do
    <<Message.binary(:ping), RakNet.Server.timestamp(base_time)::size(64)>>
  end

  defp make_pong_buffer(ping_time, base_time) do
    <<Message.binary(:pong), ping_time::size(64), RakNet.Server.timestamp(base_time)::size(64)>>
  end

  # Assume a high-but-not-crazy ping until the connection negotiation is finished (for the purpose of scheduling retries)
  defp rtt(%State{last_rtts: []}), do: 200
  defp rtt(%State{last_rtts: rtts}), do: Enum.sum(rtts) / length(rtts)
end
