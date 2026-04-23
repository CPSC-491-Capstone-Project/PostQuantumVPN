#ifndef _PQVPN_TESTS_BIT_UTILS_TESTS_HPP_
#define _PQVPN_TESTS_BIT_UTILS_TESTS_HPP_

#include "test_utils.hpp"
#include "bit_utils.hpp"

#include <array>
#include <string>
#include <span>

using namespace core::utils;

// Converts a span to a readable string for test_helper comparisons
static std::string SpanToStr(std::span<const uint8_t> v) {
    std::string s = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        s += std::to_string(v[i]);
        if (i + 1 < v.size()) s += ", ";
    }
    s += "]";
    return s;
}

// 0x01 = 00000001 in bits (LSB first per spec)
bool BitUtilsTest_BitsToBytes_Basic() {
    std::array<uint8_t, 8> bits = {1,0,0,0,0,0,0,0};
    std::array<uint8_t, 1> result{};
    std::array<uint8_t, 1> expected = {0x01};
    BitsToBytes(bits, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// All zero bits --> all zero bytes
bool BitUtilsTest_BitsToBytes_Zero() {
    std::array<uint8_t, 16> bits{};
    std::array<uint8_t, 2> result{};
    std::array<uint8_t, 2> expected{};
    BitsToBytes(bits, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// All one bits --> all 0xFF bytes
bool BitUtilsTest_BitsToBytes_AllOnes() {
    std::array<uint8_t, 8> bits{};
    bits.fill(1);
    std::array<uint8_t, 1> result{};
    std::array<uint8_t, 1> expected = {0xFF};
    BitsToBytes(bits, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// 0x01 --> LSB first = {1,0,0,0,0,0,0,0}
bool BitUtilsTest_BytesToBits_Basic() {
    std::array<uint8_t, 1> bytes = {0x01};
    std::array<uint8_t, 8> result{};
    std::array<uint8_t, 8> expected = {1,0,0,0,0,0,0,0};
    BytesToBits(bytes, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// All zero bytes --> all zero bits
bool BitUtilsTest_BytesToBits_Zero() {
    std::array<uint8_t, 2> bytes{};
    std::array<uint8_t, 16> result{};
    std::array<uint8_t, 16> expected{};
    BytesToBits(bytes, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// 0xFF --> all one bits
bool BitUtilsTest_BytesToBits_AllOnes() {
    std::array<uint8_t, 1> bytes = {0xFF};
    std::array<uint8_t, 8> result{};
    std::array<uint8_t, 8> expected{};
    expected.fill(1);
    BytesToBits(bytes, result);
    return test_helper(SpanToStr(expected), SpanToStr(result));
}

// BitsToBytes(BytesToBits(B)) == B
bool BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes() {
    std::array<uint8_t, 4> original = {0xA5, 0x3C, 0xFF, 0x00};
    std::array<uint8_t, 32> bits{};
    std::array<uint8_t, 4> result{};
    BytesToBits(original, bits);
    BitsToBytes(bits, result);
    return test_helper(SpanToStr(original), SpanToStr(result));
}

// BytesToBits(BitsToBytes(b)) == b
bool BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits() {
    std::array<uint8_t, 16> original = {1,0,1,0,0,1,0,1, 0,0,1,1,1,1,0,0};
    std::array<uint8_t, 2> bytes{};
    std::array<uint8_t, 16> result{};
    BitsToBytes(original, bytes);
    BytesToBits(bytes, result);
    return test_helper(SpanToStr(original), SpanToStr(result));
}

// ============================================================================
// HexNibble tests
// ============================================================================

bool BitUtilsTest_HexNibble_Digits() {
    for (char c = '0'; c <= '9'; ++c)
        if (HexNibble(c) != c - '0') return test_helper("correct digit", std::string(1, c));
    return test_helper("1", "1");
}

bool BitUtilsTest_HexNibble_LowerAlpha() {
    for (char c = 'a'; c <= 'f'; ++c)
        if (HexNibble(c) != c - 'a' + 10) return test_helper("correct lower", std::string(1, c));
    return test_helper("1", "1");
}

bool BitUtilsTest_HexNibble_UpperAlpha() {
    for (char c = 'A'; c <= 'F'; ++c)
        if (HexNibble(c) != c - 'A' + 10) return test_helper("correct upper", std::string(1, c));
    return test_helper("1", "1");
}

bool BitUtilsTest_HexNibble_InvalidChar() {
    return test_helper("1", std::to_string(HexNibble('z') == -1
                                        && HexNibble('G') == -1
                                        && HexNibble('!') == -1
                                        && HexNibble(' ') == -1));
}

// ============================================================================
// ToHex tests
// ============================================================================

bool BitUtilsTest_ToHex_KnownValue() {
    std::array<uint8_t, 4> data = {0xde, 0xad, 0xbe, 0xef};
    return test_helper("deadbeef", ToHex(data));
}

bool BitUtilsTest_ToHex_Empty() {
    std::array<uint8_t, 0> data{};
    return test_helper("", ToHex(data));
}

bool BitUtilsTest_ToHex_SingleByte() {
    std::array<uint8_t, 1> data = {0xff};
    return test_helper("ff", ToHex(data));
}

bool BitUtilsTest_ToHex_AllZeros() {
    std::array<uint8_t, 3> data{};
    return test_helper("000000", ToHex(data));
}

// ============================================================================
// FromHex tests
// ============================================================================

bool BitUtilsTest_FromHex_KnownValue() {
    std::array<uint8_t, 4> out{};
    if (!FromHex("deadbeef", out)) return test_helper("parse", "failed");
    std::array<uint8_t, 4> expected = {0xde, 0xad, 0xbe, 0xef};
    return test_helper(SpanToStr(expected), SpanToStr(out));
}

bool BitUtilsTest_FromHex_UpperCase() {
    std::array<uint8_t, 4> out{};
    if (!FromHex("DEADBEEF", out)) return test_helper("parse", "failed");
    std::array<uint8_t, 4> expected = {0xde, 0xad, 0xbe, 0xef};
    return test_helper(SpanToStr(expected), SpanToStr(out));
}

bool BitUtilsTest_FromHex_Roundtrip() {
    std::array<uint8_t, 8> original = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    std::array<uint8_t, 8> out{};
    if (!FromHex(ToHex(original), out)) return test_helper("roundtrip", "failed");
    return test_helper(SpanToStr(original), SpanToStr(out));
}

bool BitUtilsTest_FromHex_WrongLength() {
    std::array<uint8_t, 4> out{};
    return test_helper("1", std::to_string(!FromHex("abc", out)));  // odd length
}

bool BitUtilsTest_FromHex_InvalidChar() {
    std::array<uint8_t, 2> out{};
    return test_helper("1", std::to_string(!FromHex("zzzz", out)));
}

#endif // _PQVPN_TESTS_BIT_UTILS_TESTS_HPP_
