defmodule RakNet.SystemAddressTest do
  use ExUnit.Case, async: true
  import Assertions, only: [assert_lists_equal: 2]

  test "decodes IPv4 addresses" do
    assert_lists_equal(RakNet.SystemAddress.decode_many(<<4, 63, 87, 254, 7, 187, 128, 4, 63, 87, 254, 53, 191, 104>>), [
      %{version: 4, address: {63, 87, 254, 7}, port: 48_000},
      %{version: 4, address: {63, 87, 254, 53}, port: 49_000}
    ])
  end

  test "decodes IPv6 addresses" do
    #         v6 size fam   port    flow info  address-------------------------------------------------------  scope
    ipv6_1 = <<6, 28, 30, 191, 104, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 4, 0, 24, 239, 171, 182, 206, 138, 10, 0, 0, 0>>
    ipv6_2 = <<6, 28, 30, 191, 105, 0, 0, 0, 0, 38, 7, 251, 144, 23, 135, 144, 59, 213, 146, 204, 243, 194, 122, 129, 248, 0, 0, 0, 0>>

    assert_lists_equal(RakNet.SystemAddress.decode_many(ipv6_1 <> ipv6_2), [
      %{version: 6, address: {65_152, 0, 0, 0, 1024, 6383, 43_958, 52_874}, port: 49_000},
      %{version: 6, address: {9735, 64_400, 6023, 36_923, 54_674, 52_467, 49_786, 33_272}, port: 49_001}
    ])
  end

  test "decodes a mix of IPv4 and IPv6 addresses" do
    ipv4_1 = <<4, 63, 87, 254, 7, 187, 128>>
    ipv4_2 = <<4, 63, 87, 254, 53, 191, 104>>
    ipv6_1 = <<6, 28, 30, 191, 104, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 4, 0, 24, 239, 171, 182, 206, 138, 10, 0, 0, 0>>
    ipv6_2 = <<6, 28, 30, 191, 105, 0, 0, 0, 0, 38, 7, 251, 144, 23, 135, 144, 59, 213, 146, 204, 243, 194, 122, 129, 248, 0, 0, 0, 0>>

    assert_lists_equal(RakNet.SystemAddress.decode_many(ipv6_1 <> ipv4_1 <> ipv6_2 <> ipv4_2), [
      %{version: 4, address: {63, 87, 254, 7}, port: 48_000},
      %{version: 4, address: {63, 87, 254, 53}, port: 49_000},
      %{version: 6, address: {65_152, 0, 0, 0, 1024, 6383, 43_958, 52_874}, port: 49_000},
      %{version: 6, address: {9735, 64_400, 6023, 36_923, 54_674, 52_467, 49_786, 33_272}, port: 49_001}
    ])

    assert_lists_equal(
      RakNet.SystemAddress.decode_many(ipv6_1 <> ipv4_1 <> ipv6_2 <> ipv4_2),
      RakNet.SystemAddress.decode_many(ipv4_1 <> ipv6_1 <> ipv4_2 <> ipv6_2)
    )

    assert_lists_equal(
      RakNet.SystemAddress.decode_many(ipv6_1 <> ipv4_1 <> ipv6_2 <> ipv4_2),
      RakNet.SystemAddress.decode_many(ipv6_2 <> ipv6_1 <> ipv4_2 <> ipv4_1)
    )
  end
end
