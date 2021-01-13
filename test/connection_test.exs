defmodule RakNet.ConnectionTest do
  use ExUnit.Case, async: true
  doctest RakNet.Connection
  import RakNet.Connection, only: [message_indices_from_ack: 1]

  require Assertions
  import Assertions, only: [assert_lists_equal: 2]

  @min_is_max 1
  @min_is_not_max 0
  @packet_count_1 1

  test "handles single acks" do
    assert [2] == message_indices_from_ack(<<@packet_count_1::size(16), @min_is_max::size(8), 2::little-size(24)>>)

    assert message_indices_from_ack(<<0, 1, 1, 0, 0, 0>>) == [0]
    assert message_indices_from_ack(<<0, 1, 1, 1, 0, 0>>) == [1]
    assert message_indices_from_ack(<<0, 1, 1, 3, 0, 0>>) == [3]
  end

  test "handles ack range" do
    assert_lists_equal(
      [1, 2, 3, 4],
      message_indices_from_ack(<<@packet_count_1::size(16), @min_is_not_max::size(8), 1::little-size(24), 4::little-size(24)>>)
    )

    assert_lists_equal([1, 2], message_indices_from_ack(<<0, 1, 0, 1, 0, 0, 2, 0, 0>>))
  end

  test "handles many disjoint acks" do
    assert_lists_equal(
      [0, 4, 5, 6, 8, 9, 10, 11, 48],
      message_indices_from_ack(<<
        # Packet count
        4::size(16),
        # Drop 0
        @min_is_max::size(8),
        0::little-size(24),
        # Drop 4, 5, 6
        @min_is_not_max::size(8),
        4::little-size(24),
        6::little-size(24),
        # Drop 8-11, inclusive
        @min_is_not_max::size(8),
        8::little-size(24),
        11::little-size(24),
        # Drop 48
        @min_is_max::size(8),
        48::little-size(24)
      >>)
    )
  end
end
