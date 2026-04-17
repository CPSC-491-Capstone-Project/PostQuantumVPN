#ifndef _PQVPN_TESTS_SECURE_MEMORY_TESTS_HPP_
#define _PQVPN_TESTS_SECURE_MEMORY_TESTS_HPP_

#include "test_utils.hpp"
#include "secure_memory.hpp"

#include <array>
#include <cstdint>
#include <vector>

using core::utils::ct_memcmp;
using core::utils::secure_zero;

// ============================================================================
// ct_memcmp tests
// ============================================================================

// Two identical arrays compare as equal
bool CtMemcmpTest_Equal() {
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    a.fill(0xAB);
    b.fill(0xAB);
    return test_helper("1", std::to_string(ct_memcmp(a, b)));
}

// Two different arrays compare as not equal
bool CtMemcmpTest_NotEqual() {
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    a.fill(0xAB);
    b.fill(0xCD);
    return test_helper("1", std::to_string(!ct_memcmp(a, b)));
}

// A single differing byte anywhere causes a mismatch
bool CtMemcmpTest_SingleByteDifferenceMiddle() {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    a.fill(0x01);
    b.fill(0x01);
    b[15] ^= 0xFF;
    return test_helper("1", std::to_string(!ct_memcmp(a, b)));
}

// Difference at the last byte is detected (verifies no short-circuit at end)
bool CtMemcmpTest_DifferenceAtLastByte() {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    a.fill(0x00);
    b.fill(0x00);
    b[31] = 0x01;
    return test_helper("1", std::to_string(!ct_memcmp(a, b)));
}

// Difference at the first byte is detected
bool CtMemcmpTest_DifferenceAtFirstByte() {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    a.fill(0x00);
    b.fill(0x00);
    b[0] = 0x01;
    return test_helper("1", std::to_string(!ct_memcmp(a, b)));
}

// Zero-length comparison is vacuously equal
bool CtMemcmpTest_ZeroLength() {
    std::uint8_t dummy_a = 0;
    std::uint8_t dummy_b = 0;
    return test_helper("1", std::to_string(ct_memcmp(&dummy_a, &dummy_b, 0)));
}

// Span overload: equal spans return true
bool CtMemcmpTest_SpanOverload_Equal() {
    std::vector<std::uint8_t> a(32, 0x55);
    std::vector<std::uint8_t> b(32, 0x55);
    return test_helper("1", std::to_string(ct_memcmp(
        std::span<const std::uint8_t>{a},
        std::span<const std::uint8_t>{b}
    )));
}

// Span overload: mismatched lengths return false even if contents look similar
bool CtMemcmpTest_SpanOverload_DifferentLengths() {
    std::vector<std::uint8_t> a(16, 0x55);
    std::vector<std::uint8_t> b(32, 0x55);
    return test_helper("1", std::to_string(!ct_memcmp(
        std::span<const std::uint8_t>{a},
        std::span<const std::uint8_t>{b}
    )));
}

// ============================================================================
// secure_zero tests
// ============================================================================

// secure_zero (array overload) fills the buffer with zeros
bool SecureZeroTest_ZerosArray() {
    std::array<std::uint8_t, 32> buf{};
    buf.fill(0xAB);
    secure_zero(buf);

    bool all_zero = true;
    for (auto byte : buf) {
        if (byte != 0) { all_zero = false; break; }
    }
    return test_helper("1", std::to_string(all_zero));
}

// secure_zero (raw pointer overload) fills the region with zeros
bool SecureZeroTest_ZerosRawPointer() {
    std::array<std::uint8_t, 64> buf{};
    buf.fill(0xFF);
    secure_zero(buf.data(), buf.size());

    bool all_zero = true;
    for (auto byte : buf) {
        if (byte != 0) { all_zero = false; break; }
    }
    return test_helper("1", std::to_string(all_zero));
}

// secure_zero on a zero-length region is a no-op and does not crash
bool SecureZeroTest_ZeroLength() {
    std::array<std::uint8_t, 4> buf{};
    buf.fill(0xCC);
    secure_zero(buf.data(), 0);
    // Buffer should be untouched
    bool untouched = true;
    for (auto byte : buf) {
        if (byte != 0xCC) { untouched = false; break; }
    }
    return test_helper("1", std::to_string(untouched));
}

#endif // _PQVPN_TESTS_SECURE_MEMORY_TESTS_HPP_
