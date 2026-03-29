#include "tests.h"
#include "handshake_helpers.hpp"
#include "handshake_constants.hpp"

#include <vector>
#include <cstring>

using namespace core::handshake;
using core::cryptography::blake3::Hash256;

// ============================================================================
// Helper: build BLAKE3-256(a || b) manually for expected values
// ============================================================================
static Blake3Hash ManualMixHash(const Blake3Hash& h, ConstByteSpan data) {
    std::vector<std::uint8_t> buf;
    buf.reserve(h.size() + data.size());
    buf.insert(buf.end(), h.begin(), h.end());
    buf.insert(buf.end(), data.begin(), data.end());

    auto result = Hash256(ConstByteSpan{buf.data(), buf.size()});
    return *result;
}

// ============================================================================
// MixHash tests
// ============================================================================

// MixHash with a single byte produces BLAKE3(H || 0x42)
bool MixHashTest_SingleByte() {
    Blake3Hash h{};
    h.fill(0x00);

    std::vector<std::uint8_t> data = {0x42};
    auto expected = ManualMixHash(h, ConstByteSpan{data.data(), data.size()});

    MixHash(h, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h == expected));
}

// MixHash with empty data produces BLAKE3(H || "")
// This is valid — mixing zero bytes still re-hashes H
bool MixHashTest_EmptyData() {
    Blake3Hash h{};
    h.fill(0xAA);

    std::vector<std::uint8_t> data{};
    auto expected = ManualMixHash(h, ConstByteSpan{data.data(), data.size()});

    MixHash(h, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h == expected));
}

// MixHash is deterministic: same (H, data) -> same result
bool MixHashTest_Deterministic() {
    Blake3Hash h1{};
    Blake3Hash h2{};
    h1.fill(0x01);
    h2.fill(0x01);

    std::vector<std::uint8_t> data = {'d', 'e', 't', 'e', 'r', 'm'};

    MixHash(h1, ConstByteSpan{data.data(), data.size()});
    MixHash(h2, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h1 == h2));
}

// Different data produces different hashes
bool MixHashTest_DifferentData() {
    Blake3Hash h1{};
    Blake3Hash h2{};
    h1.fill(0x00);
    h2.fill(0x00);

    std::vector<std::uint8_t> data1 = {0x01};
    std::vector<std::uint8_t> data2 = {0x02};

    MixHash(h1, ConstByteSpan{data1.data(), data1.size()});
    MixHash(h2, ConstByteSpan{data2.data(), data2.size()});

    return test_helper("1", std::to_string(h1 != h2));
}

// Different starting H produces different results for same data
bool MixHashTest_DifferentStartingHash() {
    Blake3Hash h1{};
    Blake3Hash h2{};
    h1.fill(0x00);
    h2.fill(0xFF);

    std::vector<std::uint8_t> data = {0x42};

    MixHash(h1, ConstByteSpan{data.data(), data.size()});
    MixHash(h2, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h1 != h2));
}

// Chaining: MixHash(MixHash(H, a), b) != MixHash(MixHash(H, b), a)
// Order of mixing matters (transcript binding property)
bool MixHashTest_OrderMatters() {
    Blake3Hash h_ab{};
    Blake3Hash h_ba{};
    h_ab.fill(0x00);
    h_ba.fill(0x00);

    std::vector<std::uint8_t> a = {0x01};
    std::vector<std::uint8_t> b = {0x02};

    MixHash(h_ab, ConstByteSpan{a.data(), a.size()});
    MixHash(h_ab, ConstByteSpan{b.data(), b.size()});

    MixHash(h_ba, ConstByteSpan{b.data(), b.size()});
    MixHash(h_ba, ConstByteSpan{a.data(), a.size()});

    return test_helper("1", std::to_string(h_ab != h_ba));
}

// MixHash(H, a || b) != MixHash(MixHash(H, a), b)
// Single concatenated mix differs from two sequential mixes
bool MixHashTest_ConcatVsSequential() {
    Blake3Hash h_concat{};
    Blake3Hash h_seq{};
    h_concat.fill(0x00);
    h_seq.fill(0x00);

    std::vector<std::uint8_t> a = {0x01, 0x02};
    std::vector<std::uint8_t> b = {0x03, 0x04};

    // Concat: MixHash(H, a || b)
    std::vector<std::uint8_t> ab;
    ab.insert(ab.end(), a.begin(), a.end());
    ab.insert(ab.end(), b.begin(), b.end());
    MixHash(h_concat, ConstByteSpan{ab.data(), ab.size()});

    // Sequential: MixHash(MixHash(H, a), b)
    MixHash(h_seq, ConstByteSpan{a.data(), a.size()});
    MixHash(h_seq, ConstByteSpan{b.data(), b.size()});

    return test_helper("1", std::to_string(h_concat != h_seq));
}

// Known-answer test: H=all-zeros, data="abc"
// Expected = BLAKE3(0x00*32 || "abc")
bool MixHashTest_KnownAnswer_ZeroHash_Abc() {
    Blake3Hash h{};
    h.fill(0x00);

    std::vector<std::uint8_t> data = {'a', 'b', 'c'};

    // Build expected: BLAKE3(0x00*32 || 0x61 0x62 0x63)
    std::vector<std::uint8_t> preimage(32, 0x00);
    preimage.push_back('a');
    preimage.push_back('b');
    preimage.push_back('c');
    auto expected = Hash256(ConstByteSpan{preimage.data(), preimage.size()});
    if (!expected) return test_helper("hash", "nullopt");

    MixHash(h, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h == *expected));
}

// Known-answer test using protocol initial hash
// MixHash(InitialHash(), responder_pubkey) should match manual computation
bool MixHashTest_KnownAnswer_ProtocolInitialHash() {
    Blake3Hash h = InitialHash();

    // Simulate a 32-byte responder static public key
    std::vector<std::uint8_t> fake_pubkey(32);
    for (std::size_t i = 0; i < 32; ++i) {
        fake_pubkey[i] = static_cast<std::uint8_t>(i);
    }

    auto expected = ManualMixHash(h, ConstByteSpan{fake_pubkey.data(), fake_pubkey.size()});

    MixHash(h, ConstByteSpan{fake_pubkey.data(), fake_pubkey.size()});

    return test_helper("1", std::to_string(h == expected));
}

// Large data: mixing 4 KB of patterned data succeeds and matches reference
bool MixHashTest_LargeData() {
    Blake3Hash h{};
    h.fill(0x55);

    std::vector<std::uint8_t> data(4096);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto expected = ManualMixHash(h, ConstByteSpan{data.data(), data.size()});

    MixHash(h, ConstByteSpan{data.data(), data.size()});

    return test_helper("1", std::to_string(h == expected));
}