defmodule RakNet.ReliabilityLayer.Reliability do
  @moduledoc "Taken from RakNet's PacketPriority.h"

  @names_and_vals %{
    :unreliable => 0,
    :unreliable_sequenced => 1,
    :reliable => 2,
    :reliable_ordered => 3,
    :reliable_sequenced => 4,

    # These are the same as unreliable/reliable/reliable ordered, except that the business logic provider
    # will get an :ack message when the client acknowledges receipt
    :unreliable_ack_receipt => 5,
    :reliable_ack_receipt => 6,
    :reliable_ordered_ack_receipt => 7
  }

  @vals_and_names Map.new(@names_and_vals, fn {name, val} -> {val, name} end)

  @doc """
  The message name atom for this binary message; :error if we don't recognize it
  """
  def name(reliability_binary) when is_integer(reliability_binary), do: Map.get(@vals_and_names, reliability_binary, :error)

  def binary(reliability_name) when is_atom(reliability_name), do: Map.fetch!(@names_and_vals, reliability_name)

  def valid?(reliability_atom) when is_atom(reliability_atom), do: Map.has_key?(@names_and_vals, reliability_atom)

  def is_reliable?(reliability_binary) when is_integer(reliability_binary), do: reliability_binary in [2, 3, 4, 6, 7]
  def is_reliable?(reliability_atom) when is_atom(reliability_atom), do: binary(reliability_atom) in [2, 3, 4, 6, 7]

  def is_ordered?(reliability_binary) when is_integer(reliability_binary), do: reliability_binary == 3
  def is_ordered?(reliability_atom) when is_atom(reliability_atom), do: reliability_atom == :reliable_ordered

  def is_sequenced?(reliability_binary) when is_integer(reliability_binary), do: reliability_binary in [1, 3, 4, 7]
  def is_sequenced?(reliability_atom) when is_atom(reliability_atom), do: binary(reliability_atom) in [1, 3, 4, 7]

  def needs_client_ack?(reliability_binary) when is_integer(reliability_binary), do: reliability_binary in [5, 6, 7]
  def needs_client_ack?(reliability_atom) when is_atom(reliability_atom), do: binary(reliability_atom) in [5, 6, 7]
end

defmodule RakNet.ReliabilityLayer.Packet do
  @moduledoc "See ReliabilityLayer.cpp, ReliabilityLayer::WriteToBitStreamFromInternalPacket()"
  alias RakNet.ReliabilityLayer.Reliability

  @enforce_keys [:reliability, :buffer]
  defstruct priority: 4,
            reliability: Reliability.binary(:reliable_ordered),
            has_split: 0,
            length: -1,

            # Used for internal packets only
            identifier_ack: nil,

            # Used for all reliable types
            message_index: nil,

            # Used for UNRELIABLE_SEQUENCED, RELIABLE_SEQUENCED
            sequencing_index: nil,

            # Used for UNRELIABLE_SEQUENCED, RELIABLE_SEQUENCED, RELIABLE_ORDERED.
            order_index: nil,
            order_channel: 0,

            # Split packets only
            split_count: nil,
            split_id: nil,
            split_index: nil,

            # The actual (encapsulated) packet data
            buffer: nil

  # credo:disable-for-next-line
  def valid?(%RakNet.ReliabilityLayer.Packet{} = p) do
    msg_idx_ok = not Reliability.is_reliable?(p.reliability) or (is_integer(p.message_index) and p.message_index >= 0)
    order_idx_ok = not Reliability.is_sequenced?(p.reliability) or (is_integer(p.order_index) and p.order_index >= 0)

    split_ok =
      p.has_split == 0 or
        (is_integer(p.split_count) and p.split_count > 0 and
           is_integer(p.split_id) and is_integer(p.split_index))

    msg_idx_ok and order_idx_ok and split_ok and
      p.priority >= 0 and p.priority < 0xF and
      Reliability.valid?(p.reliability) and p.buffer != nil
  end
end
