#ifndef CPP_TEMPLATE_TESTS_H_
#define CPP_TEMPLATE_TESTS_H_

#include <string_view>
#include <iostream>


// =============================================================================
// Random Tests
// =============================================================================

bool RandomTest_SingletonInit();
bool RandomTest_ZeroBytes();
bool RandomTest_OneByte();
bool RandomTest_EightBytes();
bool RandomTest_OneKilobyte();
bool RandomTest_3319Bytes();

// =============================================================================
// Bit Utils Tests
// =============================================================================
bool BitUtilsTest_BitsToBytes_Basic();
bool BitUtilsTest_BitsToBytes_Zero();
bool BitUtilsTest_BitsToBytes_AllOnes();
bool BitUtilsTest_BytesToBits_Basic();
bool BitUtilsTest_BytesToBits_Zero();
bool BitUtilsTest_BytesToBits_AllOnes();
bool BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits();
bool BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes();

// =============================================================================
// Future Test Categories
// =============================================================================

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result);

#endif  // CPP_TEMPLATE_TESTS_H_