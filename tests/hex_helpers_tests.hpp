#ifndef _PQVPN_TESTS_HEX_HELPERS_TESTS_HPP_
#define _PQVPN_TESTS_HEX_HELPERS_TESTS_HPP_

#include "test_utils.hpp"
#include "hex_helpers.tpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

using core::utils::ToHexString;

// =============================================================================
// Integer types
// =============================================================================

bool HexTest_Uint8() {
    return test_helper("0xFF", ToHexString(static_cast<uint8_t>(0xFF)))
        && test_helper("0x00", ToHexString(static_cast<uint8_t>(0x00)))
        && test_helper("0x0A", ToHexString(static_cast<uint8_t>(0x0A)));
}

bool HexTest_Uint16() {
    return test_helper("0xCAFE", ToHexString(static_cast<uint16_t>(0xCAFE)))
        && test_helper("0x0000", ToHexString(static_cast<uint16_t>(0x0000)))
        && test_helper("0x00FF", ToHexString(static_cast<uint16_t>(0x00FF)));
}

bool HexTest_Uint32() {
    return test_helper("0xDEADBEEF", ToHexString(static_cast<uint32_t>(0xDEADBEEF)))
        && test_helper("0x00000000", ToHexString(static_cast<uint32_t>(0x00000000)))
        && test_helper("0x0000FFFF", ToHexString(static_cast<uint32_t>(0x0000FFFF)));
}

bool HexTest_Uint64() {
    return test_helper("0xDEADBEEFCAFEBABE", ToHexString(static_cast<uint64_t>(0xDEADBEEFCAFEBABE)))
        && test_helper("0x0000000000000000", ToHexString(static_cast<uint64_t>(0x0000000000000000)))
        && test_helper("0x00000000FFFFFFFF", ToHexString(static_cast<uint64_t>(0x00000000FFFFFFFF)));
}

// =============================================================================
// span<const uint8_t>
// =============================================================================

bool HexTest_Span_Empty() {
    std::span<const uint8_t> empty{};
    return test_helper("", ToHexString(empty));
}

bool HexTest_Span_SingleByte() {
    const uint8_t byte = 0xAB;
    std::span<const uint8_t> s{&byte, 1};
    return test_helper("0xAB", ToHexString(s));
}

bool HexTest_Span_MultiByte() {
    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::span<const uint8_t> s{data};
    return test_helper("0xDEADBEEF", ToHexString(s));
}

// =============================================================================
// vector<uint8_t>
// =============================================================================

bool HexTest_Vector_Empty() {
    std::vector<uint8_t> empty{};
    return test_helper("", ToHexString(empty));
}

bool HexTest_Vector_SingleByte() {
    std::vector<uint8_t> data{0x42};
    return test_helper("0x42", ToHexString(data));
}

bool HexTest_Vector_MultiByte() {
    std::vector<uint8_t> data{0xCA, 0xFE, 0xBA, 0xBE};
    return test_helper("0xCAFEBABE", ToHexString(data));
}

// =============================================================================
// std::array<uint8_t, N>
// =============================================================================

bool HexTest_Array() {
    std::array<uint8_t, 4> data{0x01, 0x23, 0x45, 0x67};
    return test_helper("0x01234567", ToHexString(data));
}
#endif // _PQVPN_TESTS_HEX_HELPERS_TESTS_HPP_
