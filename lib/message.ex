defmodule RakNet.Message do
  @moduledoc """
  Message types that RakNet can send. These are the first 8 bits of the packet.
  Follows RakLib protocol: https://github.com/pmmp/RakLib/tree/master/src/protocol
  """

  @names_and_vals %{
    # These come from RakNet's DefaultMessageIDTypes enum (in MessageIdentifiers.h)
    :ping => 0x00,
    :unconnected_ping => 0x01,
    :unconnected_ping_open_connections => 0x02,
    :pong => 0x03,
    :open_connection_request_1 => 0x05,
    :open_connection_reply_1 => 0x06,
    :open_connection_request_2 => 0x07,
    :open_connection_reply_2 => 0x08,
    # ID_CONNECTION_REQUEST
    :client_connect => 0x09,
    # ID_CONNECTION_REQUEST_ACCEPTED: Tell the client the connection request accepted
    :server_handshake => 0x10,
    # ID_CONNECTION_ATTEMPT_FAILED: Sent to the player when a connection request cannot be completed
    :connection_attempt_failed => 0x11,
    # ID_NEW_INCOMING_CONNECTION: A remote client has successfully connected
    :client_handshake => 0x13,
    :client_disconnect => 0x15,
    # ID_CONNECTION_LOST: Reliable packet delivery failed, connection closed
    :connection_lost => 0x16,
    # ID_INCOMPATIBLE_PROTOCOL_VERSION
    :incompatible_version => 0x19,
    :unconnected_pong => 0x1C,
    :advertise_system => 0x1D,

    # These come from RakNet's reliability layer and "congestion control"---they are datagram headers
    # The indices are the priority (0 to 15)
    :data_packet_0 => 0x80,
    :data_packet_1 => 0x81,
    :data_packet_2 => 0x82,
    :data_packet_3 => 0x83,
    :data_packet_4 => 0x84,
    :data_packet_5 => 0x85,
    :data_packet_6 => 0x86,
    :data_packet_7 => 0x87,
    :data_packet_8 => 0x88,
    :data_packet_9 => 0x89,
    :data_packet_A => 0x8A,
    :data_packet_B => 0x8B,
    :data_packet_C => 0x8C,
    :data_packet_D => 0x8D,
    :data_packet_E => 0x8E,
    :data_packet_F => 0x8F,
    :nack => 0xA0,
    :ack => 0xC0
  }

  @msg_names MapSet.new(Map.keys(@names_and_vals))
  @msg_binary_vals MapSet.new(Map.values(@names_and_vals))
  @vals_and_names Map.new(@names_and_vals, fn {name, val} -> {val, name} end)

  @doc """
  Set of all message types listed above---:ping, :unconnected_ping, :pong, etc.
  """
  def known_message_names, do: @msg_names

  @doc """
  Set of all hex values that act as packet type identifiers.
  E.g., 0x0 for ping, 0x3 for pong, 0x1d for advertise system, etc.
  """
  def known_messages, do: @msg_binary_vals

  @doc """
  True if we have a name atom for this message type
  """
  def is_known?(message_binary) when is_integer(message_binary), do: MapSet.member?(@msg_binary_vals, message_binary)

  def is_protocol_data?(message_binary) when is_integer(message_binary), do: message_binary in 0x80..0x8F

  @doc """
  The message name atom for this binary message; :error if we don't recognize it
  """
  def name(message_binary) when is_integer(message_binary), do: Map.get(@vals_and_names, message_binary, :error)

  def binary(message_name) when is_atom(message_name), do: Map.fetch!(@names_and_vals, message_name)

  # "Magic" bytes used to distinguish offline messages from garbage
  def offline_msg_id, do: <<0, 255, 255, 0, 254, 254, 254, 254, 253, 253, 253, 253, 18, 52, 86, 120>>
end
