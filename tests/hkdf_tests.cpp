#include "tests.h"
#include "hkdf.hpp"

// Tests for the HKDF wrapper covering extract output size, expand output size,
// derive key determinism, different inputs produce different outputs, and roundtrip correctness.

using namespace core::cryptography::hkdf;

static std::string BytesMatch(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return "size_mismatch";
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return "mismatch";
    }
    return "match";
}

// Extract output should be 32 bytes for SHA-256
bool HkdfTest_Extract_OutputSize() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ikm  = {0xAA, 0xBB, 0xCC, 0xDD};

    auto result = Extract(salt, ikm);
    if (!result) return test_helper("extract", "nullopt");

    return test_helper("32", std::to_string(result->size()));
}

// Extract output should not be empty
bool HkdfTest_Extract_NotEmpty() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> ikm  = {0x04, 0x05, 0x06};

    auto result = Extract(salt, ikm);
    if (!result) return test_helper("extract", "nullopt");

    return test_helper("1", std::to_string(!result->empty()));
}

// Expand output should match the requested size
bool HkdfTest_Expand_OutputSize() {
    std::vector<std::uint8_t> prk  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                      0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    std::vector<std::uint8_t> info = {0xAA, 0xBB};
    std::size_t requestedLen = 64;

    auto result = Expand(prk, info, requestedLen);
    if (!result) return test_helper("expand", "nullopt");

    return test_helper("64", std::to_string(result->size()));
}

// DeriveKey output should match the requested size
bool HkdfTest_DeriveKey_OutputSize() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ikm  = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> info = {0x11, 0x22, 0x33};
    std::size_t requestedLen = 32;

    auto result = DeriveKey(salt, ikm, info, requestedLen);
    if (!result) return test_helper("derivekey", "nullopt");

    return test_helper("32", std::to_string(result->size()));
}

// Same inputs should always produce the same output
bool HkdfTest_DeriveKey_Deterministic() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ikm  = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> info = {0x11, 0x22, 0x33};

    auto result1 = DeriveKey(salt, ikm, info, 32);
    auto result2 = DeriveKey(salt, ikm, info, 32);

    if (!result1 || !result2) return test_helper("derivekey", "nullopt");

    return test_helper("match", BytesMatch(*result1, *result2));
}

// Different salt should produce different output
bool HkdfTest_DeriveKey_DifferentSalt() {
    std::vector<std::uint8_t> salt1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> salt2 = {0x05, 0x06, 0x07, 0x08};
    std::vector<std::uint8_t> ikm   = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> info  = {0x11, 0x22, 0x33};

    auto result1 = DeriveKey(salt1, ikm, info, 32);
    auto result2 = DeriveKey(salt2, ikm, info, 32);

    if (!result1 || !result2) return test_helper("derivekey", "nullopt");

    return test_helper("mismatch", BytesMatch(*result1, *result2));
}

// Different key material should produce different output
bool HkdfTest_DeriveKey_DifferentIKM() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ikm1 = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> ikm2 = {0x11, 0x22, 0x33, 0x44};
    std::vector<std::uint8_t> info = {0x11, 0x22, 0x33};

    auto result1 = DeriveKey(salt, ikm1, info, 32);
    auto result2 = DeriveKey(salt, ikm2, info, 32);

    if (!result1 || !result2) return test_helper("derivekey", "nullopt");

    return test_helper("mismatch", BytesMatch(*result1, *result2));
}

// Extract then expand should match DeriveKey
bool HkdfTest_Roundtrip_ExtractExpand_MatchesDeriveKey() {
    std::vector<std::uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> ikm  = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> info = {0x11, 0x22, 0x33};

    auto prk = Extract(salt, ikm);
    if (!prk) return test_helper("extract", "nullopt");

    auto expanded = Expand(*prk, info, 32);
    if (!expanded) return test_helper("expand", "nullopt");

    auto derived = DeriveKey(salt, ikm, info, 32);
    if (!derived) return test_helper("derivekey", "nullopt");

    return test_helper("match", BytesMatch(*expanded, *derived));
}