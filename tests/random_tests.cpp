#include "tests.h"
#include "random.hpp"
#include <iostream>

using namespace core::utils;

bool RandomTest_SingletonInit() {
    auto bytes = Random::GenerateNRandomBytes(1);
    return test_helper("1", std::to_string(bytes.size()));
}

bool RandomTest_ZeroBytes() {
    auto bytes = Random::GenerateNRandomBytes(0);
    return test_helper("0", std::to_string(bytes.size()));
}


bool RandomTest_OneByte() {
    auto bytes = Random::GenerateNRandomBytes(1);
    return test_helper("1", std::to_string(bytes.size()));
}


bool RandomTest_EightBytes() {
    auto bytes = Random::GenerateNRandomBytes(8);
    return test_helper("8", std::to_string(bytes.size()));
}


bool RandomTest_OneKilobyte() {
    auto bytes = Random::GenerateNRandomBytes(1024);
    return test_helper("1024", std::to_string(bytes.size()));
}

bool RandomTest_3319Bytes() {
    auto bytes = Random::GenerateNRandomBytes(3319);
    return test_helper("3319", std::to_string(bytes.size()));
}