#include "tests.h"
#include "bit_utils.hpp"
#include <string>

using namespace core::utils;

// Converts a vector to a readable string for test_helper comparisons
static std::string VecToStr(const std::vector<uint8_t>& v) {
    std::string s = "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        s += std::to_string(v[i]);
        if (i + 1 < v.size()) s += ", ";
    }
    s += "]";
    return s;
}

// 0x01 = 00000001 in bits (LSB first per spec)
bool BitUtilsTest_BitsToBytes_Basic() {
    std::vector<uint8_t> bits = { 1,0,0,0,0,0,0,0 };
    std::vector<uint8_t> expected = { 0x01 };
    return test_helper(VecToStr(expected), VecToStr(BitsToBytes(bits)));
}

// All zero bits --> all zero bytes
bool BitUtilsTest_BitsToBytes_Zero() {
    std::vector<uint8_t> bits(16, 0);
    std::vector<uint8_t> expected(2, 0x00);
    return test_helper(VecToStr(expected), VecToStr(BitsToBytes(bits)));
}

// All one bits --> all 0xFF bytes
bool BitUtilsTest_BitsToBytes_AllOnes() {
    std::vector<uint8_t> bits(8, 1);
    std::vector<uint8_t> expected = { 0xFF };
    return test_helper(VecToStr(expected), VecToStr(BitsToBytes(bits)));
}

// 0x01 --> LSB first = {1,0,0,0,0,0,0,0}
bool BitUtilsTest_BytesToBits_Basic() {
    std::vector<uint8_t> bytes = { 0x01 };
    std::vector<uint8_t> expected = { 1,0,0,0,0,0,0,0 };
    return test_helper(VecToStr(expected), VecToStr(BytesToBits(bytes)));
}

// All zero bytes --> all zero bits
bool BitUtilsTest_BytesToBits_Zero() {
    std::vector<uint8_t> bytes(2, 0x00);
    std::vector<uint8_t> expected(16, 0);
    return test_helper(VecToStr(expected), VecToStr(BytesToBits(bytes)));
}

// 0xFF --> all one bits
bool BitUtilsTest_BytesToBits_AllOnes() {
    std::vector<uint8_t> bytes = { 0xFF };
    std::vector<uint8_t> expected(8, 1);
    return test_helper(VecToStr(expected), VecToStr(BytesToBits(bytes)));
}

// BitsToBytes(BytesToBits(B)) == B
bool BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes() {
    std::vector<uint8_t> original = { 0xA5, 0x3C, 0xFF, 0x00 };
    auto result = BitsToBytes(BytesToBits(original));
    return test_helper(VecToStr(original), VecToStr(result));
}

// BytesToBits(BitsToBytes(b)) == b
bool BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits() {
    std::vector<uint8_t> original = { 1,0,1,0,0,1,0,1, 0,0,1,1,1,1,0,0 };
    auto result = BytesToBits(BitsToBytes(original));
    return test_helper(VecToStr(original), VecToStr(result));
}