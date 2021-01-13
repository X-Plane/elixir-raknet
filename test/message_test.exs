defmodule RakNet.MessageTest do
  use ExUnit.Case, async: true

  test "lists the message name atoms" do
    known_msg_names = RakNet.Message.known_message_names()
    expected_atoms = MapSet.new([:ping, :unconnected_ping, :pong, :client_disconnect, :data_packet_8, :ack])
    assert MapSet.subset?(expected_atoms, known_msg_names)
  end

  test "lists the message binary values" do
    known_msgs = RakNet.Message.known_messages()
    expected_vals = MapSet.new([0, 1, 2, 3, 5, 6, 7, 8, 9, 0x10, 0x13, 0x15, 0x1C, 0x1D, 0x80, 0x8F, 0xA0, 0xC0])
    assert MapSet.subset?(expected_vals, known_msgs)

    expected_missing = MapSet.new([4, 0x0A, 0x12, 0x14, 0x1B, 0x1E])
    assert MapSet.disjoint?(known_msgs, expected_missing)

    assert Enum.all?(Enum.map(expected_vals, &RakNet.Message.is_known?/1))
    assert !Enum.any?(Enum.map(expected_missing, &RakNet.Message.is_known?/1))
  end

  test "fetches message name atoms from binary values" do
    assert RakNet.Message.name(0) == :ping
    assert RakNet.Message.name(0x13) == :client_handshake
    assert RakNet.Message.name(0x13) == :client_handshake

    assert RakNet.Message.name(0x14) == :error
    assert RakNet.Message.name(0x1B) == :error
  end
end
