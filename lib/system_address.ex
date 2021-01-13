defmodule RakNet.SystemAddress do
  @moduledoc "Tools for encoding & decoding IP addresses & ports"

  def encode(%{version: 4, address: {o1, o2, o3, o4}, port: port}),
    do: <<4::size(8), o1::unsigned-size(8), o2::unsigned-size(8), o3::unsigned-size(8), o4::unsigned-size(8), port::unsigned-size(16)>>

  def encode(%{version: 6, address: {h1, h2, h3, h4, h5, h6, h7, h8}, port: port}) do
    <<6::size(8), 28::unsigned-size(8), 30::unsigned-size(8), port::unsigned-size(16), 0::size(32), h1::unsigned-size(16),
      h2::unsigned-size(16), h3::unsigned-size(16), h4::unsigned-size(16), h5::unsigned-size(16), h6::unsigned-size(16),
      h7::unsigned-size(16), h8::unsigned-size(16), 0::size(32)>>
  end

  def encode(%{address: addr, port: _port} = args) do
    encode(Map.put(args, :version, ip_version(addr)))
  end

  # Octet and hextet versions
  def ip_version({_, _, _, _}), do: 4
  def ip_version({_, _, _, _, _, _, _, _}), do: 6

  # Host-and-port patterns
  def ip_version({{_, _, _, _}, port}) when is_integer(port), do: 4
  def ip_version({{_, _, _, _, _, _, _, _}, port}) when is_integer(port), do: 6

  def decode_many(addresses_and_ports) when is_bitstring(addresses_and_ports) do
    decode_address_port(addresses_and_ports)
  end

  defp decode_address_port(bin, prev \\ [])

  defp decode_address_port(<<4::size(8), address::binary-size(4), port::unsigned-size(16), rest::binary>>, prev) do
    <<o1::unsigned-size(8), o2::unsigned-size(8), o3::unsigned-size(8), o4::unsigned-size(8)>> = address
    decode_address_port(rest, [%{version: 4, address: {o1, o2, o3, o4}, port: port} | prev])
  end

  # Note: ipv6 addresses are serialized as their whole sockaddr_in6 struct
  # Fields are:
  #  1. Length of the struct (28 bytes == 224 bits)
  #  2. sa_family_t, fixed value of AF_INET6 == 30 (0x1e)
  #  3. port
  #  4. flow info (???)
  #  5. in6_addr (128 bits)
  #  6. scope ID (???)
  defp decode_address_port(<<6::size(8), 28::unsigned-size(8), 30::unsigned-size(8), ipv6_body::bitstring-size(208), rest::binary>>, prev) do
    <<port::unsigned-size(16), _::unsigned-size(32), addr::bitstring-size(128), _::unsigned-size(32)>> = ipv6_body

    <<a1::unsigned-size(16), a2::unsigned-size(16), a3::unsigned-size(16), a4::unsigned-size(16), a5::unsigned-size(16),
      a6::unsigned-size(16), a7::unsigned-size(16), a8::unsigned-size(16)>> = addr

    decode_address_port(rest, [%{version: 6, address: {a1, a2, a3, a4, a5, a6, a7, a8}, port: port} | prev])
  end

  defp decode_address_port(<<>>, prev) when is_list(prev), do: prev
end
