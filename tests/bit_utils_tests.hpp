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
#endif // _PQVPN_TESTS_BIT_UTILS_TESTS_HPP_
