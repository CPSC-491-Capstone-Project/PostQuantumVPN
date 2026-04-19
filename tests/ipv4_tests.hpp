#ifndef _PQVPN_TESTS_IPV4_TESTS_HPP_
#define _PQVPN_TESTS_IPV4_TESTS_HPP_

#include "test_utils.hpp"
#include "ipv4.hpp"

#include <bit>

using namespace core::network;

// =============================================================================
// Construction & round-trip
// =============================================================================

bool IPv4Test_DefaultIsZero() {
    constexpr IPv4 addr;
    return addr.ToHostOrder() == 0
        && addr.IsValid();
}

bool IPv4Test_FromOctets() {
    constexpr IPv4 addr(192, 168, 1, 42);
    constexpr auto octets = addr.Octets();
    return octets[0] == 192
        && octets[1] == 168
        && octets[2] ==   1
        && octets[3] ==  42
        && addr.IsValid();
}

bool IPv4Test_FromUint32() {
    // 10.0.0.1 in host order = (10 << 24) | 1
    constexpr std::uint32_t expected = (10u << 24) | 1u;
    constexpr IPv4 addr(expected);
    constexpr auto octets = addr.Octets();
    return addr.ToHostOrder() == expected
        && octets[0] == 10
        && octets[3] ==  1
        && addr.IsValid();
}

bool IPv4Test_FromString_Valid() {
    IPv4 addr(std::string("172.16.0.255"));
    auto octets = addr.Octets();
    return addr.IsValid()
        && octets[0] == 172
        && octets[1] ==  16
        && octets[2] ==   0
        && octets[3] == 255;
}

bool IPv4Test_FromString_Malformed() {
    IPv4 bad(std::string("not.an.ip"));
    return !bad.IsValid()
        && bad.ToHostOrder() == 0;
}

bool IPv4Test_Roundtrip_OctetsToString() {
    IPv4 addr(127, 0, 0, 1);
    return addr.ToString() == "127.0.0.1";
}

bool IPv4Test_Roundtrip_StringToOctets() {
    IPv4 addr(std::string("255.255.255.0"));
    auto o = addr.Octets();
    return o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 0;
}

// =============================================================================
// Endian-correct network order
// =============================================================================

bool IPv4Test_NetworkOrder() {
    // 1.2.3.4 — regardless of host endianness, the network-order
    // bytes in memory must be [0x01, 0x02, 0x03, 0x04]
    constexpr IPv4 addr(1, 2, 3, 4);
    constexpr std::uint32_t net = addr.ToNetworkOrder();

    // Inspect the in-memory byte layout
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&net);
    return bytes[0] == 1 && bytes[1] == 2 && bytes[2] == 3 && bytes[3] == 4;
}

bool IPv4Test_HostNetworkRoundtrip() {
    // Converting host -> network -> back to host must be identity.
    // std::byteswap is C++23 and not yet available on Apple Clang,
    // so we inline the byte-swap manually.
    constexpr IPv4 original(192, 168, 50, 7);
    constexpr std::uint32_t net = original.ToNetworkOrder();

    constexpr std::uint32_t host = [&]() constexpr {
        if constexpr (std::endian::native == std::endian::big) {
            return net;
        } else {
            return ((net & 0xFF000000u) >> 24) |
                   ((net & 0x00FF0000u) >>  8) |
                   ((net & 0x0000FF00u) <<  8) |
                   ((net & 0x000000FFu) << 24);
        }
    }();

    return host == original.ToHostOrder();
}

// =============================================================================
// Comparison
// =============================================================================

bool IPv4Test_Equality() {
    constexpr IPv4 a(10, 0, 0, 1);
    IPv4 b(std::string("10.0.0.1"));
    constexpr IPv4 c(10, 0, 0, 2);
    return a == b && !(a == c);
}

bool IPv4Test_Ordering() {
    constexpr IPv4 low(10, 0, 0, 1);
    constexpr IPv4 high(10, 0, 0, 2);
    return low < high && !(high < low);
}

// =============================================================================
// Consteval constants
// =============================================================================

bool IPv4Test_Constants() {
    constexpr auto any       = IPv4::Any();
    constexpr auto loopback  = IPv4::Loopback();
    constexpr auto broadcast = IPv4::Broadcast();

    return any.ToHostOrder() == 0
        && loopback.Octets()  == std::array<std::uint8_t, 4>{127, 0, 0, 1}
        && broadcast.Octets() == std::array<std::uint8_t, 4>{255, 255, 255, 255};
}

// =============================================================================
// Constexpr evaluation
// =============================================================================

bool IPv4Test_FullyConstexpr() {
    constexpr IPv4 addr(192, 168, 1, 1);
    constexpr auto octets = addr.Octets();
    constexpr auto host   = addr.ToHostOrder();
    constexpr auto net    = addr.ToNetworkOrder();
    constexpr bool valid  = addr.IsValid();

    static_assert(octets[0] == 192);
    static_assert(valid);
    static_assert(host != 0);
    static_assert(net != 0);

    return true;
}

#endif // _PQVPN_TESTS_IPV4_TESTS_HPP_
