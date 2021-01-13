defmodule RakNet.PacketTest do
  use ExUnit.Case

  @test_data_packet <<25, 62, 69, 23, 124, 1, 0, 32, 0, 224, 105, 1, 0, 1, 0, 0, 0, 144, 9, 89, 211, 245, 50, 93, 224, 84, 166, 81, 195, 12,
                      94, 253, 127, 183, 0, 128, 255, 127, 255, 127, 195, 56, 128, 64, 0>>

  @tag packet: true
  test "decodes unreliable sequenced data packets" do
    assert %{encapsulated_packets: [packet | []]} = RakNet.Packet.decode_with_timestamp(@test_data_packet)
    assert packet.priority == 4
    assert packet.reliability == :unreliable_sequenced
    assert packet.length == 28
    assert is_nil(packet.message_index)
    assert not is_nil(packet.sequencing_index)
  end
end
