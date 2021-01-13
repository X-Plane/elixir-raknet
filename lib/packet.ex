defmodule RakNet.Packet do
  @moduledoc "Encoding & decoding utils for RakLib data, taken from ExRakLib"
  require Logger
  alias RakNet.ReliabilityLayer
  alias RakNet.ReliabilityLayer.Reliability

  def decode_with_timestamp(<<timestamp::size(32), data::binary>>) do
    Map.put(decode_no_timestamp(data), :timestamp, timestamp)
  end

  def decode_no_timestamp(data, internal \\ false) do
    <<sequence_number::little-size(24), rest::binary>> = :erlang.iolist_to_binary(data)

    %{
      sequence_number: sequence_number,
      encapsulated_packets: decode_no_timestamp(rest, [], internal),
      timestamp: -1
    }
  rescue
    e ->
      Logger.error(inspect(e))
      %{sequence_number: -1, encapsulated_packets: []}
  end

  defp decode_no_timestamp("", encapsulated_packets, _internal) do
    Enum.reverse(encapsulated_packets)
  end

  defp decode_no_timestamp(rest, encapsulated_packets, internal) do
    {packet, rest} = decode_encapsulated_packet(rest, internal)
    decode_no_timestamp(rest, [packet | encapsulated_packets], internal)
  end

  def encode(%{sequence_number: seq, encapsulated_packets: packets, timestamp: ts}) when ts >= 0 do
    :erlang.iolist_to_binary([<<ts::size(32), seq::little-size(24)>>, Enum.map(packets, &encode_encapsulated_packet(&1, false))])
  end

  def encode(%{sequence_number: seq_number, encapsulated_packets: encapsulated}, internal \\ false) do
    :erlang.iolist_to_binary([<<seq_number::little-size(24)>>, Enum.map(encapsulated, &encode_encapsulated_packet(&1, internal))])
  end

  def decode_encapsulated_packet(data, internal) do
    <<reliability::unsigned-size(3), has_split::unsigned-size(5), post_header::binary>> = data

    is_reliable = Reliability.is_reliable?(reliability)
    is_sequenced = Reliability.is_sequenced?(reliability)

    {length, identifier_ack, post_length} =
      if internal do
        <<length::size(32), identifier_ack::size(32), rest::binary>> = post_header
        {length, identifier_ack, rest}
      else
        <<length::size(16), rest::binary>> = post_header
        {trunc(Float.ceil(length / 8)), nil, rest}
      end

    # message_index is actually the sequencing index for :unreliable_sequenced
    {message_index, post_reliability} =
      if is_reliable or is_sequenced do
        <<message_index::little-size(24), rest::binary>> = post_length
        {message_index, rest}
      else
        {nil, post_length}
      end

    {order_index, order_channel, post_ordering} =
      if is_sequenced do
        <<order_index::little-size(24), order_channel::size(8), rest::binary>> = post_reliability
        {order_index, order_channel, rest}
      else
        {nil, nil, post_reliability}
      end

    {split_count, split_id, split_index, post_split} =
      if has_split > 0 do
        <<split_count::size(32), split_id::size(16), split_index::size(32), rest::binary>> = post_ordering
        {split_count, split_id, split_index, rest}
      else
        {nil, nil, nil, post_ordering}
      end

    <<buffer::binary-size(length), rest::binary>> = post_split

    {%ReliabilityLayer.Packet{
       reliability: Reliability.name(reliability),
       has_split: has_split,
       length: length,
       identifier_ack: identifier_ack,
       message_index: if(is_reliable, do: message_index, else: nil),
       sequencing_index: if(is_reliable, do: nil, else: message_index),
       order_index: order_index,
       order_channel: order_channel,
       split_count: split_count,
       split_id: split_id,
       split_index: split_index,
       buffer: buffer
     }, rest}
  end

  def encode_encapsulated_packet(%ReliabilityLayer.Packet{} = p, internal) do
    if ReliabilityLayer.Packet.valid?(p) do
      is_reliable = Reliability.is_reliable?(p.reliability)
      is_sequenced = Reliability.is_sequenced?(p.reliability)
      index = if is_reliable, do: p.message_index, else: p.sequencing_index

      # TODO: Support splitting: https://github.com/mhsjlw/node-raknet/blob/master/src/client.js#L144
      <<Reliability.binary(p.reliability)::unsigned-size(3), p.has_split::unsigned-size(5)>> <>
        if internal do
          <<byte_size(p.buffer)::size(32), p.identifier_ack::size(32)>>
        else
          <<trunc(byte_size(p.buffer) * 8)::size(16)>>
        end <>
        if is_reliable or is_sequenced do
          <<index::little-size(24)>> <>
            if is_sequenced do
              <<p.order_index::little-size(24), p.order_channel::size(8)>>
            else
              <<>>
            end
        else
          <<>>
        end <>
        if p.has_split > 0 do
          <<p.split_count::size(32), p.split_id::size(16), p.split_index::size(32)>>
        else
          <<>>
        end <>
        p.buffer
    else
      Logger.error("Invalid packet: #{inspect(p, binaries: :as_binaries, limit: :infinity)}")
      <<>>
    end
  end
end
