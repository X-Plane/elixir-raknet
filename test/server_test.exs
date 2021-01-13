defmodule RakNet.ServerTest do
  use ExUnit.Case
  require Logger
  import RakNet.Packet, only: [decode_with_timestamp: 1, decode_no_timestamp: 1]

  @moduledoc """
  This is an acceptance test (in the sense popularized in the C++ community by Clare Macrae.

  We run through the exact sequence of packets that an official RakNet sample app sends, and assert
  that we send the correct responses.
  """

  # I've hard-coded this as my GUID in my copy of the RakNet code, so that I can create reproducible packet tests
  @fixed_id 12_345_678_901_234_567_890
  @localhost {127, 0, 0, 1}
  @localhost6 {0, 0, 0, 0, 0, 0, 0, 1}

  test "handles client connection negotiation" do
    {_server_pid, server_host_and_port} = start_server(49_101)
    {client_send, client_send_padded} = make_client_send_fns(49_100, server_host_and_port)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_responded("0600ffff00fefefefefdfdfdfd12345678ab54a98ceb1f0ad20005d4") end)

    # :open_connection_request_2 -> :open_connection_reply_2
    client_send.("0700ffff00fefefefefdfdfdfd123456780480fffffebfcd05d400059bb99c3c475c")

    assert server_responded("0800ffff00fefefefefdfdfdfd12345678ab54a98ceb1f0ad20480fffffebfcc05d400", normalize_ip_addresses: true),
           "Failed to respond to open connection request 2"

    # :data_packet_4[:client_connect] -> :data_packet_4[:server_handshake]
    client_send.("840000004001080000000900059bb98e0d2f4a00000000000000160052756d70656c7374696c74736b696e")

    assert server_responded_many([
             {"8400000060030000000000000000100480fffffebfcc0000043f57fe32bfcd04ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000000000000000000160000000000004345",
              [
                normalize_ip_addresses: true,
                # Ignore the timestamp at the end
                discard_last_bytes: 4
              ]},
             {"c0000101000000", []}
           ]),
           "Failed to respond to client_connect with handshake and/or ack client ordered packet 0"

    # Have the client ack the handshake
    client_send.("c0000101000000")
    # :data_packet_4[client_handshake] requires a pong response from its ping
    client_send.(
      "840100006002f001000000000000130480fffffebfcd043f57fe32bfcc04ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000000000000000040160000000000000025000048000000000000000025"
    )

    # :data_packet_4[ping]
    client_send.("8402000000004800000000000000002f")

    # :data_packet_4[ping, pong for 0x25, pong for 0x2f]
    # "8401000000004800000000000000402d000088030000000000000025000000000000402d00008803000000000000002f000000000000402d",
    assert server_sent_packets_with(2, [
             {:ack, [1, 2]},
             {:ping, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable}
           ]),
           "Failed to handle client handshake and additional enqueued pong"

    # Ack the data packet with the ping and 2 pongs
    client_send.("c0000101010000")
    # 2 pongs to respond to our pings
    client_send.("84030000000088030000000000003ca4000000000000002c000088030000000000003ca4000000000000002c")

    assert server_responded("c0000101030000"), "Failed to respond to ack client's packet 3"

    # Send an actual "business logic" packet---a chat message "ahoy"
    client_send.("841a00006000280800000200000061686f7900")
    # Note that the "a" gets dropped from our "ahoy" packet, because the first byte of the message is always the client packet type
    assert receive_business_logic_msg() == "hoy" <> <<0>>, "Failed to receive 'ahoy' business logic message"
  end

  @tag xplane: true
  test "handles client negotiation with embedded timestamps" do
    has_embedded_timestamp = true
    # Send timestamps with datagrams!
    {_server_pid, server_host_and_port} = start_xplane_server(49_108)
    {client_send, client_send_padded} = make_client_send_fns(49_109, server_host_and_port)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)

    # :open_connection_request_2 -> :open_connection_reply_2
    client_send.("0700FFFF00FEFEFEFEFDFDFDFD12345678043F57FE07BB8005D422A2C5FD8AF0CF58")
    assert server_sent_packet_with({:open_connection_reply_2, :connection_negotiation}), "Failed to respond to open connection request 2"

    # :data_packet_4[:client_connect] -> :data_packet_4[:server_handshake]
    client_send.("840001703F0000004000900000000922A2C5FD8AF0CF58000000000000005D00")

    assert server_sent_packets_with(2, [{:server_handshake, :reliable_ordered}, {:ack, [0]}], true),
           "Failed to respond to client_connect with handshake and/or ack client ordered packet 0"

    # Have the client ack the handshake
    client_send.("C000000020000101000000")
    # :data_packet_4[client_handshake] requires a pong response from its ping
    client_send.(
      "84000216EE0100006019E00100000000000013043F57FE07BB80061C1EBF6800000000FE80000000000000C2A53EFFFE188D771F000000061C1EBF6800000000FE8000000000000018AB2FDACB39D7F202000000061C1EBF6800000000FE80000000000000CBAD3755438672141C000000061C1EBF68000000002607FC20E12A44EBE8F61BF2372CAB6500000000061C1EBF6800000000FE80000000000000DD135BB99B71EB3216000000061C1EBF68000000002607FC20E12A44EB10A1ABB78F934D9300000000061C1EBF6800000000FE800000000000004FD46183DE0250B315000000061C1EBF68000000002607FC20E12A44EBD143E3D178F8727800000000061C1EBF68000000002607FC20E12A44EBE497120B5A43099E00000000061C1EBF68000000002607FB901787903B319202F400D6266300000000061C1EBF6800000000FE8000000000000000381638AF01F1F703000000061C1EBF6800000000FE80000000000000590E28A7A8EE2D3514000000061C1EBF6800000000FE80000000000000397893EEA9E580A113000000049B69AB37BF68061C1EBF68000000002607FB901787903B043F38E29EE8C16000000000061C1EBF68000000002607FB901787903B097329AED1ACD39B00000000061C1EBF6800000000FE8000000000000004A607634B35B90308000000061C1EBF68000000002605A601AD7804000CE83F74A5CB264500000000061C1EBF6800000000FE80000000000000C2A53EFFFE188D770C000000061C1EBF6800000000FE80000000000000C017C6FFFE53F8660B000000061C1EBF6800000000FE80000000000000040018EFABB6CE8A0A000000061C1EBF6800000000FD7465726D6E7573000DA8FCEB6EE7BF00000000061C1EBF6800000000FE800000000000001AAA9D708BA12BB30D000000061C1EBF6800000000FD7465726D6E7573000CA8FCEB6EE7BF00000000061C1EBF68000000002607FB901787903B88E0C05F76E6D09900000000061C1EBF68000000002607FB901787903B802F37306E7ABD4200000000061C1EBF68000000002605A601AD780400A4F5EA8182BC7797000000000456018792BF68043F57FE35BF68061C1EBF6800000000FD7465726D6E7573000CA8FCEB6EE7BF000000000000000000000000000000000000007000004800000000000000007D"
    )

    # :data_packet_4[ping, pong for 0x25, pong for 0x2f]
    # "8401000000004800000000000000402d000088030000000000000025000000000000402d00008803000000000000002f000000000000402d",
    assert server_sent_packets_with(
             2,
             [
               {:ack, [1]},
               {:ping, :unreliable},
               {:pong, :unreliable},
               {:pong, :unreliable}
             ],
             has_embedded_timestamp
           ),
           "Failed to handle client handshake and additional enqueued pong"
  end

  @tag slow: true
  test "resends unacknowledged packets" do
    # ------------------------------------------------------------------------------------------------------------------
    # BEGIN COPYPASTA
    # Everything up to the Process.sleep() is copypasta from the connection negotiation test!
    # ------------------------------------------------------------------------------------------------------------------
    {_server_pid, server_host_and_port} = start_server(49_103)
    {client_send, client_send_padded} = make_client_send_fns(49_102, server_host_and_port)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)

    # :open_connection_request_2 -> :open_connection_reply_2
    client_send.("0700ffff00fefefefefdfdfdfd123456780480fffffebfcf05d400059bb99c3c475c")
    assert server_sent_packet_with({:open_connection_reply_2, :connection_negotiation}), "Failed to respond to open connection request 2"

    # :data_packet_4[:client_connect] -> :data_packet_4[:server_handshake]
    client_send.("840000004001080000000900059bb98e0d2f4a00000000000000160052756d70656c7374696c74736b696e")

    assert server_sent_packets_with(2, [{:server_handshake, :reliable_ordered}, {:ack, [0]}]),
           "Failed to respond to client_connect with handshake and/or ack client ordered packet 0"

    # ------------------------------------------------------------------------------------------------------------------
    # END COPYPASTA
    # ------------------------------------------------------------------------------------------------------------------

    # Sleep while the client deliberately does *not* send an ack for the :server_handshake packet
    Process.sleep(1100)
    assert server_sent_packet_with({:server_handshake, :reliable_ordered}), "Failed to resend reliable packet :server_handshake"

    Process.sleep(1100)
    assert server_sent_packet_with({:server_handshake, :reliable_ordered}), "Failed to resend :server_handshake a second time"

    # Ack the handshake (packet index 2, not 0, since reliable packet 0 got resent twice)
    # TODO: Should we be keeping track of the packet's *old* index and allowing ack based on that? (0 in this case)
    client_send.("c0000101020000")

    receive do
      {:protocol_msg, msg_raw} -> raise RuntimeError, message: "Server should not have sent any more messages; sent #{inspect(msg_raw)}"
    after
      1_100 -> :ok
    end
  end

  @tag slow: true
  test "connections time out after not hearing from the client" do
    timeout_ms = 500
    {_server_pid, server_host_and_port} = start_server(49_105, timeout_ms)
    {_client_send, client_send_padded} = make_client_send_fns(49_104, server_host_and_port)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)

    :timer.sleep(timeout_ms + 100)
    matching_pids = Registry.lookup(RakNet.Connection, {@localhost, 49_104})

    if not Enum.empty?(matching_pids) do
      [{_, pid} | _] = matching_pids

      if Process.alive?(pid) do
        # Flush all messages on the process
        :sys.get_state(pid)
      end

      assert not Process.alive?(pid)
    end
  end

  defmodule AckRequestingClient do
    @enforce_keys [:handle_data, :handle_ack, :connection_pid]
    defstruct handle_data: nil, handle_ack: nil, connection_pid: nil

    def new(connection_pid, test_pid) do
      :timer.apply_interval(100, AckRequestingClient, :bug_the_user, [connection_pid])

      %AckRequestingClient{
        connection_pid: connection_pid,
        handle_data: fn _packet_type, data -> send(test_pid, {:business_logic_msg, data}) end,
        handle_ack: fn send_receipt_id -> send(test_pid, {:business_logic_ack, send_receipt_id}) end
      }
    end

    def bug_the_user(connection_pid) do
      RakNet.Connection.send(connection_pid, :reliable_ack_receipt, "please acknowledge")
    end
  end

  defimpl RakNet.Client, for: AckRequestingClient do
    def new(_client_struct, connection_pid, test_pid), do: AckRequestingClient.new(connection_pid, test_pid)
    def receive(client, packet_type, packet_buffer, _time_comp), do: client.handle_data.(packet_type, packet_buffer)
    def got_ack(client, send_receipt_id), do: client.handle_ack.(send_receipt_id)
    def disconnect(_client), do: :ok
  end

  test "forwards acks to game logic client" do
    # ------------------------------------------------------------------------------------------------------------------
    # BEGIN COPYPASTA
    # Everything up to the Process.sleep() is copypasta from the connection negotiation test!
    # ------------------------------------------------------------------------------------------------------------------

    {_server_pid, server_host_and_port} = start_server(49_201, 1_000, AckRequestingClient)

    {client_send, client_send_padded} = make_client_send_fns(49_200, server_host_and_port)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)

    # :open_connection_request_2 -> :open_connection_reply_2
    client_send.("0700ffff00fefefefefdfdfdfd123456780480fffffebfcd05d400059bb99c3c475c")
    assert server_sent_packet_with({:open_connection_reply_2, :connection_negotiation}), "Failed to respond to open connection request 2"

    # :data_packet_4[:client_connect] -> :data_packet_4[:server_handshake]
    client_send.("840000004001080000000900059bb98e0d2f4a00000000000000160052756d70656c7374696c74736b696e")

    assert server_sent_packets_with(2, [{:server_handshake, :reliable_ordered}, {:ack, [0]}]),
           "Failed to respond to client_connect with handshake and/or ack client ordered packet 0"

    # Have the client ack the handshake
    client_send.("c0000101000000")
    # :data_packet_4[client_handshake] requires a pong response from its ping
    client_send.(
      "840100006002f001000000000000130480fffffebfcd043f57fe32bfcc04ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000000000000000040160000000000000025000048000000000000000025"
    )

    # :data_packet_4[ping]
    client_send.("8402000000004800000000000000002f")

    # :data_packet_4[ping, pong for 0x25, pong for 0x2f]
    assert server_sent_packets_with(2, [
             {:ack, [1, 2]},
             {:ping, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable}
           ]),
           "Failed to handle client handshake and additional enqueued pong"

    # Ack the data packet with the ping and 2 pongs
    client_send.("c0000101010000")
    # 2 pongs to respond to our pings
    client_send.("84030000000088030000000000003ca4000000000000002c000088030000000000003ca4000000000000002c")

    assert server_responded("c0000101030000"), "Failed to respond to ack client's packet 3"

    # ------------------------------------------------------------------------------------------------------------------
    # END COPYPASTA
    # ------------------------------------------------------------------------------------------------------------------

    # Have the server send a value that requests an ack
    assert server_sent_packet_with({"please acknowledge", :reliable_ack_receipt})
    client_send.("c0000101020000")
    assert receive_business_logic_ack()
  end

  @tag ipv6: true
  test "handles IPv6 connections" do
    {_server_pid, _server_host_and_port} = start_server(49_211, 1_000, AckRequestingClient)
    {client_send, client_send_padded} = make_client_send_fns(49_210, {@localhost6, 49_211}, 6)

    # :open_connection_request_1 -> :open_connection_reply_1
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)

    # :open_connection_request_2 -> :open_connection_reply_2
    client_send.("0700ffff00fefefefefdfdfdfd123456780480fffffebfcd05d400059bb99c3c475c")
    assert server_sent_packet_with({:open_connection_reply_2, :connection_negotiation}), "Failed to respond to open connection request 2"

    # :data_packet_4[:client_connect] -> :data_packet_4[:server_handshake]
    client_send.("840000004001080000000900059bb98e0d2f4a00000000000000160052756d70656c7374696c74736b696e")

    assert server_sent_packets_with(2, [{:server_handshake, :reliable_ordered}, {:ack, [0]}]),
           "Failed to respond to client_connect with handshake and/or ack client ordered packet 0"

    # Have the client ack the handshake
    client_send.("c0000101000000")
    # :data_packet_4[client_handshake] requires a pong response from its ping
    client_send.(
      "840100006002f001000000000000130480fffffebfcd043f57fe32bfcc04ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000004ffffffff000000000000000040160000000000000025000048000000000000000025"
    )

    # :data_packet_4[ping]
    client_send.("8402000000004800000000000000002f")

    # :data_packet_4[ping, pong for 0x25, pong for 0x2f]
    assert server_sent_packets_with(2, [
             {:ack, [1, 2]},
             {:ping, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable},
             {:pong, :unreliable}
           ]),
           "Failed to handle client handshake and additional enqueued pong"

    # Ack the data packet with the ping and 2 pongs
    client_send.("c0000101010000")
    # 2 pongs to respond to our pings
    client_send.("84030000000088030000000000003ca4000000000000002c000088030000000000003ca4000000000000002c")

    assert server_responded("c0000101030000"), "Failed to respond to ack client's packet 3"

    # Have the server send a value that requests an ack
    assert server_sent_packet_with({"please acknowledge", :reliable_ack_receipt})
    client_send.("c0000101020000")
    assert receive_business_logic_ack()
  end

  test "server complains if you send data packets without having negotiated a connection" do
    {_server_pid, server_host_and_port} = start_server(49_107)
    {client_send, client_send_padded} = make_client_send_fns(49_106, server_host_and_port)

    # Attempt to ack some non-existent packet
    client_send.("c0000101010000")

    assert server_sent_packet_with({:connection_lost, :connection_negotiation}), "Server should nag to establish a connection before ack"

    # Send a data packet out of the blue
    client_send.("84030000000088030000000000003ca4000000000000002c000088030000000000003ca4000000000000002c")
    assert server_sent_packet_with({:connection_lost, :connection_negotiation}), "Server should nag connect before sending data"

    # Start opening a connection, but then send a data packet before completing the connection negotiation
    open_conn_req_1_with_retries(client_send_padded, fn -> server_sent_packet_with({:open_connection_reply_1, :connection_negotiation}) end)
    client_send.("841a00006000280800000200000061686f7900")
    assert server_sent_packet_with({:connection_lost, :connection_negotiation}), "Server should nag to finish connection negotiation"
  end

  test "server survives connection crash" do
    {server_pid, server_host_and_port} = start_server(49_900)

    # Start a bunch of connections
    [{live_client_send, port_to_keep_alive} | send_fns_and_ports_to_kill] =
      Enum.map(1..10, fn i ->
        port = 49_900 + i
        {client_send, client_send_padded} = make_client_send_fns(port, server_host_and_port)
        # :open_connection_request_1 -> :open_connection_reply_1
        open_conn_req_1_with_retries(client_send_padded, fn ->
          server_sent_packet_with({:open_connection_reply_1, :connection_negotiation})
        end)

        {client_send, port}
      end)

    ports_to_kill = Enum.map(send_fns_and_ports_to_kill, fn {_, port} -> port end)

    # Kill all but one
    Enum.each(ports_to_kill, fn port ->
      [{_, pid}] = Registry.lookup(RakNet.Connection, {@localhost, port})
      Process.exit(pid, :kill)
      assert not Process.alive?(pid), "Failed to kill process for port #{port}"
    end)

    assert Process.alive?(server_pid), "Server died when we killed its connections"

    [{_, live_pid}] = Registry.lookup(RakNet.Connection, {@localhost, port_to_keep_alive})
    :sys.get_state(live_pid)
    assert Process.alive?(live_pid), "PID died unexpectedly"

    # :open_connection_request_2 -> :open_connection_reply_2
    live_client_send.("0700ffff00fefefefefdfdfdfd123456780480fffffebfcd05d400059bb99c3c475c")
    assert server_sent_packet_with({:open_connection_reply_2, :connection_negotiation}), "Failed to respond to open connection request 2"
    assert Process.alive?(server_pid), "Server died when we killed its connections"
  end

  defmodule DummyClient do
    defstruct handle_data: nil

    def accept_data(client, packet_type, buffer) do
      client.handle_data.(packet_type, buffer)
      client
    end
  end

  defimpl RakNet.Client, for: DummyClient do
    def new(_, _, test_pid), do: %DummyClient{handle_data: fn _type, data -> send(test_pid, {:business_logic_msg, data}) end}
    def receive(client, packet_type, packet_buffer, _time_comp), do: DummyClient.accept_data(client, packet_type, packet_buffer)
    def got_ack(client, _send_receipt_id), do: client
    def disconnect(_client), do: :ok
  end

  defp start_server(port, timeout_ms \\ 10_000, client_module \\ nil) do
    test_pid = self()

    {:ok, server_pid} =
      RakNet.Server.start_link(if(client_module, do: client_module, else: DummyClient), port,
        client_timeout_ms: timeout_ms,
        client_data: test_pid,
        server_identifier: <<@fixed_id::size(64)>>,
        host: @localhost,
        open_ipv6_socket: System.get_env("SEPARATE_IPV6_PORT") != "false",
        send: fn _, packet, _client ->
          send(test_pid, {:protocol_msg, packet})
        end
      )

    {server_pid, {@localhost, port}}
  end

  defp start_xplane_server(port) do
    test_pid = self()

    {:ok, server_pid} =
      RakNet.Server.start_link(DummyClient, port,
        client_data: test_pid,
        server_identifier: <<@fixed_id::size(64)>>,
        host: @localhost,
        send: fn _, packet, _client -> send(test_pid, {:protocol_msg, packet}) end,
        # Begin X-Plane-specific #defines!
        include_timestamp_with_datagrams: true,
        max_number_of_internal_ids: 30
      )

    {server_pid, {@localhost, port}}
  end

  defp make_client_send_fns(client_port, server_host_and_port, ip_version \\ 4) do
    socket =
      if ip_version == 4 do
        Socket.UDP.open!(client_port, local: [address: @localhost], version: 4)
      else
        Socket.UDP.open!(client_port, local: [address: @localhost6], version: 6)
      end

    client_send_padded = fn packet_string, pad_to_byte_length ->
      data = packet_decode(packet_string)
      pad_length = max(pad_to_byte_length * 8 - bit_size(data), 0)
      Socket.Datagram.send!(socket, data <> <<0::size(pad_length)>>, server_host_and_port)
    end

    client_send = fn packet_string -> client_send_padded.(packet_string, 0) end
    {client_send, client_send_padded}
  end

  defp packet_decode(packet_hex_string, pad_to_byte_length \\ 0) do
    data = Base.decode16!(packet_hex_string, case: :mixed)
    pad_length = max(pad_to_byte_length * 8 - bit_size(data), 0)
    data <> <<0::size(pad_length)>>
  end

  defp server_responded(packet_hex_string, opts \\ []) when is_binary(packet_hex_string) do
    server_responded_many([{packet_hex_string, opts}])
  end

  defp server_sent_packet_with(packet_spec, has_embedded_timestamp \\ false) do
    server_sent_packets_with(1, [packet_spec], has_embedded_timestamp)
  end

  defp server_sent_packets_with(num_packets, packet_spec, has_embedded_timestamp \\ false) when is_list(packet_spec) do
    actual_types_and_reliabilities =
      num_packets
      |> receive_n_sends()
      |> Enum.flat_map(&parse_packet_type(&1, has_embedded_timestamp))

    if Enum.sort(packet_spec) == Enum.sort(actual_types_and_reliabilities) do
      true
    else
      Logger.error("Expected packets: #{inspect(packet_spec, limit: :infinity)}")
      Logger.error("Received packets: #{inspect(actual_types_and_reliabilities, limit: :infinity)}")
      false
    end
  end

  # credo:disable-for-next-line
  defp parse_packet_type(<<type::size(8), remainder::binary>>, has_embedded_timestamp) do
    ack = RakNet.Message.binary(:ack)

    decode_fn = if has_embedded_timestamp, do: &decode_with_timestamp/1, else: &decode_no_timestamp/1
    ack_timestamp_bits = if has_embedded_timestamp, do: 32, else: 0

    case type do
      ^ack ->
        [{:ack, RakNet.Connection.message_indices_from_ack(drop_leading_bits(remainder, ack_timestamp_bits))}]

      x when x in 0x80..0x8F ->
        Enum.map(decode_fn.(remainder)[:encapsulated_packets], fn packet ->
          <<encapsulated_type::size(8), _::binary>> = packet.buffer

          case RakNet.Message.name(encapsulated_type) do
            :error -> {packet.buffer, packet.reliability}
            name -> {name, packet.reliability}
          end
        end)

      x when x in 0x05..0x16 ->
        [{RakNet.Message.name(type), :connection_negotiation}]
    end
  end

  defp server_responded_many(packet_specs) when is_list(packet_specs) do
    packets_and_xforms =
      Enum.map(packet_specs, fn {packet_hex_string, opts} ->
        # Replace loopback adapter's IP+port combo (which is what happens when you run the RakNet samples in the terminal)
        # with "plain-old localhost" (which is what we get when we run the ExUnit test)
        normalize_ips =
          if Keyword.get(opts, :normalize_ip_addresses, false) do
            fn bits ->
              bits
              |> String.replace(<<128, 255, 255, 254, 191, 204>>, <<127, 0, 0, 1, 191, 204>>)
              |> String.replace(<<128, 255, 255, 254, 191, 206>>, <<127, 0, 0, 1, 191, 206>>)
              |> String.replace(<<63, 87, 254, 50, 191, 205>>, <<127, 0, 0, 1, 191, 205>>)
              |> String.replace(<<63, 87, 254, 50, 191, 207>>, <<127, 0, 0, 1, 191, 207>>)
            end
          else
            & &1
          end

        drop_trailing = fn bits ->
          new_length_bytes = byte_size(bits) - Keyword.get(opts, :discard_last_bytes, 0)
          if new_length_bytes > 2, do: <<bits::binary-size(new_length_bytes)>>, else: bits
        end

        drop_bits = Keyword.get(opts, :discard_first_bytes, 0) * 8
        drop_leading = &drop_leading_bits(&1, drop_bits)

        transform = fn bits -> bits |> drop_leading.() |> drop_trailing.() |> normalize_ips.() end
        expected_raw = packet_decode(packet_hex_string, Keyword.get(opts, :pad_to_byte_length, 0))
        {expected_raw, transform.(expected_raw), transform}
      end)

    reduce_remove_nil = fn x, acc -> if x, do: [x | acc], else: acc end

    msgs_raw = receive_n_sends(length(packets_and_xforms))

    missing_expected =
      packets_and_xforms
      |> Enum.map(fn {raw, expected, transform} ->
        has_match = Enum.any?(msgs_raw, fn msg_raw -> transform.(msg_raw) == expected end)
        if has_match, do: nil, else: raw
      end)
      |> Enum.reduce([], reduce_remove_nil)

    if length(missing_expected) > 0 do
      Logger.error("Failed to receive expected message(s):")
      Enum.each(missing_expected, fn msg -> Logger.error("#{inspect(msg, limit: :infinity)}") end)
    end

    unexpected_msgs =
      msgs_raw
      |> Enum.map(fn msg_raw ->
        matched = Enum.any?(packets_and_xforms, fn {_raw, expected, transform} -> transform.(msg_raw) == expected end)
        if matched, do: nil, else: msg_raw
      end)
      |> Enum.reduce([], reduce_remove_nil)

    if length(unexpected_msgs) > 0 do
      Logger.error("Received unexpected message(s):")
      Enum.each(unexpected_msgs, fn msg -> Logger.error("#{inspect(msg, limit: :infinity)}") end)
    end

    Enum.empty?(unexpected_msgs) and Enum.empty?(missing_expected)
  end

  defp drop_leading_bits(data, num_bits) do
    <<_::size(num_bits), remainder::binary>> = data
    remainder
  end

  # With enough tests going at once, we can overwhelm the network interface---it's okay if we have to try this again
  defp open_conn_req_1_with_retries(client_send_padded, success_check, max_attempts \\ 10, attempt \\ 1)

  defp open_conn_req_1_with_retries(client_send_padded, success_check, max_attempts, attempt) when max_attempts > attempt do
    client_send_padded.("0500ffff00fefefefefdfdfdfd1234567806", 1464)
    assert success_check.()
  rescue
    _ ->
      Process.sleep(250 + :rand.uniform(1250))
      open_conn_req_1_with_retries(client_send_padded, success_check, max_attempts, attempt + 1)
  end

  defp open_conn_req_1_with_retries(_client_send_padded, _success_check, _max_attempts, _attempt) do
    raise RuntimeError, message: "Failed to receive open_connection_reply_1 from our open_connection_request_1"
  end

  def receive_n_sends(n) when is_integer(n) do
    Enum.map(1..n, fn _ ->
      receive do
        {:protocol_msg, msg_raw} -> msg_raw
      after
        1_000 ->
          raise RuntimeError, message: "Didn't receive enough messages"
      end
    end)
  end

  def receive_business_logic_msg do
    receive do
      {:business_logic_msg, msg_raw} -> msg_raw
    after
      5_000 ->
        raise RuntimeError, message: "Didn't receive a business logic message"
    end
  end

  def receive_business_logic_ack do
    receive do
      {:business_logic_ack, msg_raw} -> msg_raw
    after
      5_000 ->
        raise RuntimeError, message: "Didn't receive a business logic ack"
    end
  end
end
