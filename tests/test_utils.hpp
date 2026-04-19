#ifndef _PQVPN_TESTS_TEST_UTILS_HPP_
#define _PQVPN_TESTS_TEST_UTILS_HPP_

// Shared test infrastructure included by every test header.
//
// Intentionally minimal — only the things every test needs:
//   - test_helper() forward declaration (defined in test_runner.cpp)
//   - Standard headers those functions depend on

#include <functional>
#include <iostream>
#include <string>
#include <string_view>

// Compares expected vs result. On mismatch prints a diff and returns false.
// Defined in test_runner.cpp, which includes all test headers and is therefore
// the single translation unit where both the declaration and definition live.
bool test_helper(std::string_view expected, std::string_view result);

#endif // _PQVPN_TESTS_TEST_UTILS_HPP_
