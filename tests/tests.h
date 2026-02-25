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
// Future Test Categories
// =============================================================================

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result);

#endif  // CPP_TEMPLATE_TESTS_H_