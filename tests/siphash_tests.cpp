#include "tests.h"
#include "siphash.hpp"
#include "hex_helpers.tpp"

#include <string_view>
#include <vector>
#include <cstdint>


using namespace core::cryptography::siphash;
using core::utils::ToHexString;

static constexpr std::string_view TEST_KEY = "TEST_KEY";
static constexpr std::string_view TEST_MSG = "Test Message";

bool SipHashTest_BlankKey_BlankInput() {
    auto key = NormalizeKey("");
    auto data = NormalizeData("");

    SipHash24 hasher;
    Result hash = hasher(key, data);

    std::string expected = "0x1E924B9D737700D7"; 
    return test_helper(expected, ToHexString(hash));
}

bool SipHashTest_BlankKey_NormalInput() {
    auto key = NormalizeKey("");
    auto data = NormalizeData(TEST_MSG);

    SipHash24 hasher;
    Result hash = hasher(key, data);

    std::string expected = "0xFAB63990186AD9E3";
    return test_helper(expected, ToHexString(hash));
}

bool SipHashTest_NormalKey_BlankInput() {
    auto key = NormalizeKey(TEST_KEY);
    auto data = NormalizeData("");

    SipHash24 hasher;
    Result hash = hasher(key, data);

    std::string expected = "0x56236AEEC4AA32DA"; 
    return test_helper(expected, ToHexString(hash));
}

bool SipHashTest_NormalKey_NormalInput() {
    auto key = NormalizeKey(TEST_KEY);
    auto data = NormalizeData(TEST_MSG);

    SipHash24 hasher;
    Result hash = hasher(key, data);

    std::string expected = "0x2CB628E13DC4013F";
    return test_helper(expected, ToHexString(hash));
}

bool SipHashTest_NormalKey_LargeInput() {
    auto key = NormalizeKey(TEST_KEY);

    std::string input;
    input.reserve(1054);
    for (int i = 0; i < 17; ++i) {
        input += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    }
    auto data = NormalizeData(std::string_view{input});

    SipHash24 hasher;
    Result hash = hasher(key, data);

    std::string expected = "0xCBB9639F0B5F4F88";
    return test_helper(expected, ToHexString(hash));
}