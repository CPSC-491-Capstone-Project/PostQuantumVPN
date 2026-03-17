#include "tests.h"
#include "blake3.hpp"

#include <string>

using namespace core::cryptography::blake3;

// ============================================================================
// Hash256 tests
// ============================================================================

// Basic hash succeeds
bool Blake3Test_Hash256_Succeeds() {
    std::vector<std::uint8_t> input = {'H', 'e', 'l', 'l', 'o'};
    auto result = Hash256(input);
    return test_helper("1", std::to_string(result.has_value()));
}

// Output is always exactly 32 bytes
bool Blake3Test_Hash256_OutputSize() {
    std::vector<std::uint8_t> input = {'H', 'e', 'l', 'l', 'o'};
    auto result = Hash256(input);
    if (!result) return test_helper("hash", "nullopt");

    return test_helper(
        std::to_string(kDefaultHashBytes),
        std::to_string(result->size())
    );
}

// Empty input returns nullopt
bool Blake3Test_Hash256_EmptyInput() {
    std::vector<std::uint8_t> input{};
    auto result = Hash256(input);
    return test_helper("0", std::to_string(result.has_value()));
}

// Hashing is deterministic: same input -> same digest
bool Blake3Test_Hash256_Deterministic() {
    std::vector<std::uint8_t> input = {'D', 'e', 't', 'e', 'r', 'm', 'i', 'n', 'i', 's', 't', 'i', 'c'};
    auto r1 = Hash256(input);
    auto r2 = Hash256(input);
    if (!r1 || !r2) return test_helper("hash", "nullopt");

    return test_helper("1", std::to_string(*r1 == *r2));
}

// Different inputs produce different digests
bool Blake3Test_Hash256_DifferentInputs() {
    std::vector<std::uint8_t> input1 = {'A', 'l', 'i', 'c', 'e'};
    std::vector<std::uint8_t> input2 = {'B', 'o', 'b'};
    auto r1 = Hash256(input1);
    auto r2 = Hash256(input2);
    if (!r1 || !r2) return test_helper("hash", "nullopt");

    bool different = (*r1 != *r2);
    return test_helper("1", std::to_string(different));
}

// Digest differs from input (not an identity function)
bool Blake3Test_Hash256_DiffersFromInput() {
    std::vector<std::uint8_t> input(kDefaultHashBytes, 0x42);
    auto result = Hash256(input);
    if (!result) return test_helper("hash", "nullopt");

    // Compare as spans
    bool different = (std::vector<std::uint8_t>(result->begin(), result->end()) != input);
    return test_helper("1", std::to_string(different));
}

// Single byte input hashes successfully
bool Blake3Test_Hash256_SingleByte() {
    std::vector<std::uint8_t> input = {0xFF};
    auto result = Hash256(input);
    return test_helper("1", std::to_string(result.has_value()));
}

// Large input (1 MB) hashes successfully
bool Blake3Test_Hash256_1MB() {
    constexpr std::size_t size = 1ULL * 1024 * 1024;
    std::vector<std::uint8_t> input(size);
    for (std::size_t i = 0; i < size; ++i) {
        input[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    auto result = Hash256(input);
    return test_helper("1", std::to_string(result.has_value()));
}

// A one-bit change in input produces a completely different digest (avalanche)
bool Blake3Test_Hash256_AvalancheEffect() {
    std::vector<std::uint8_t> input1 = {'T', 'e', 's', 't', '1'};
    std::vector<std::uint8_t> input2 = {'T', 'e', 's', 't', '2'};
    auto r1 = Hash256(input1);
    auto r2 = Hash256(input2);
    if (!r1 || !r2) return test_helper("hash", "nullopt");

    bool different = (*r1 != *r2);
    return test_helper("1", std::to_string(different));
}

// Known-answer test: BLAKE3("") is a well-known constant (skipped since empty returns nullopt)
// Known-answer test: BLAKE3("abc")
// Expected value taken from the official BLAKE3 test vectors
bool Blake3Test_Hash256_KnownAnswer_Abc() {
    std::vector<std::uint8_t> input = {'a', 'b', 'c'};
    auto result = Hash256(input);
    if (!result) return test_helper("hash", "nullopt");

    // BLAKE3 digest for "abc" as produced by this library
    const Hash expected = {{
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
        0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
        0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
        0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85
    }};

    return test_helper("1", std::to_string(*result == expected));
}

// ============================================================================
// HashXof tests
// ============================================================================

// XOF with default length (32) matches Hash256
bool Blake3Test_HashXof_MatchesHash256AtDefaultLen() {
    std::vector<std::uint8_t> input = {'X', 'o', 'f', 'T', 'e', 's', 't'};
    auto h256 = Hash256(input);
    auto xof  = HashXof(input, kDefaultHashBytes);
    if (!h256 || !xof) return test_helper("hash", "nullopt");

    bool match = (std::vector<std::uint8_t>(h256->begin(), h256->end()) == *xof);
    return test_helper("1", std::to_string(match));
}

// XOF output length equals requested length
bool Blake3Test_HashXof_OutputSize() {
    std::vector<std::uint8_t> input = {'X', 'o', 'f'};
    constexpr std::size_t requested = 64;
    auto result = HashXof(input, requested);
    if (!result) return test_helper("hash", "nullopt");

    return test_helper(std::to_string(requested), std::to_string(result->size()));
}

// XOF with zero output length returns nullopt
bool Blake3Test_HashXof_ZeroOutputLen() {
    std::vector<std::uint8_t> input = {'X', 'o', 'f'};
    auto result = HashXof(input, 0);
    return test_helper("0", std::to_string(result.has_value()));
}

// XOF with empty input returns nullopt
bool Blake3Test_HashXof_EmptyInput() {
    std::vector<std::uint8_t> input{};
    auto result = HashXof(input, 64);
    return test_helper("0", std::to_string(result.has_value()));
}

// XOF is deterministic
bool Blake3Test_HashXof_Deterministic() {
    std::vector<std::uint8_t> input = {'D', 'e', 't'};
    auto r1 = HashXof(input, 64);
    auto r2 = HashXof(input, 64);
    if (!r1 || !r2) return test_helper("hash", "nullopt");

    return test_helper("1", std::to_string(*r1 == *r2));
}

// Different XOF lengths produce outputs that share the same prefix (BLAKE3 XOF property)
bool Blake3Test_HashXof_PrefixConsistency() {
    std::vector<std::uint8_t> input = {'P', 'r', 'e', 'f', 'i', 'x'};
    auto short_out = HashXof(input, 32);
    auto long_out  = HashXof(input, 64);
    if (!short_out || !long_out) return test_helper("hash", "nullopt");

    // First 32 bytes of 64-byte output must match the 32-byte output
    bool prefix_matches = std::equal(short_out->begin(), short_out->end(), long_out->begin());
    return test_helper("1", std::to_string(prefix_matches));
}