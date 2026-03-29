#include "handshake_helpers.hpp"
#include "logger.hpp"
#include "chacha20_poly1305.hpp"

#include <tuple>

using core::utils::Logger;
using core::cryptography::blake3::Hash256;
using core::cryptography::blake3::KeyedHash256;

namespace core::handshake {

void MixHash(Blake3Hash& hash, ConstByteSpan data) {
    // H = HASH(H || data)
    std::vector<std::uint8_t> buf;
    buf.reserve(hash.size() + data.size());
    buf.insert(buf.end(), hash.begin(), hash.end());
    buf.insert(buf.end(), data.begin(), data.end());

    auto result = Hash256(ConstByteSpan{buf.data(), buf.size()});

    if (!result) {
        // H is always 32 bytes, so buf is never empty.
        // Hash256 only fails on empty input - this path is unreachable
        // under normal operation, but zero the hash defensively.
        hash.fill(0);
        return;
    }

    hash = *result;
}

auto KDF1(const Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<Blake3Hash> {
    // PRK = BLAKE3_keyed(key=C, data=input)
    auto prk = KeyedHash256(
        std::span<const std::uint8_t, 32>{chaining_key},
        input
    );
 
    if (!prk) {
        Logger::Error("KDF1: KeyedHash256 failed computing PRK");
        return std::nullopt;
    }
 
    // T0 = BLAKE3_keyed(key=PRK, data=0x01)
    const std::array<std::uint8_t, 1> counter = {0x01};
    auto t0 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{counter}
    );
 
    if (!t0) {
        Logger::Error("KDF1: KeyedHash256 failed computing T0");
        return std::nullopt;
    }
 
    return *t0;
}

auto KDF2(const Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<std::tuple<Blake3Hash, Blake3Hash>> {
    // PRK = BLAKE3_keyed(key=C, data=input)
    auto prk = KeyedHash256(
        std::span<const std::uint8_t, 32>{chaining_key},
        input
    );
 
    if (!prk) {
        Logger::Error("KDF2: KeyedHash256 failed computing PRK");
        return std::nullopt;
    }
 
    // T0 = BLAKE3_keyed(key=PRK, data=0x01)
    const std::array<std::uint8_t, 1> counter1 = {0x01};
    auto t0 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{counter1}
    );
 
    if (!t0) {
        Logger::Error("KDF2: KeyedHash256 failed computing T0");
        return std::nullopt;
    }
 
    // T1 = BLAKE3_keyed(key=PRK, data=T0 || 0x02)
    std::array<std::uint8_t, 33> t0_counter2{};
    std::copy(t0->begin(), t0->end(), t0_counter2.begin());
    t0_counter2[32] = 0x02;
 
    auto t1 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{t0_counter2}
    );
 
    if (!t1) {
        Logger::Error("KDF2: KeyedHash256 failed computing T1");
        return std::nullopt;
    }
 
    return std::make_tuple(*t0, *t1);
}

auto KDF3(const Blake3Hash& chaining_key,ConstByteSpan input) -> std::optional<std::tuple<Blake3Hash, Blake3Hash, Blake3Hash>>{
    // PRK = BLAKE3_keyed(key=C, data=input)
    auto prk = KeyedHash256(
        std::span<const std::uint8_t, 32>{chaining_key},
        input
    );
 
    if (!prk) {
        Logger::Error("KDF3: KeyedHash256 failed computing PRK");
        return std::nullopt;
    }
 
    // T0 = BLAKE3_keyed(key=PRK, data=0x01)
    const std::array<std::uint8_t, 1> counter1 = {0x01};
    auto t0 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{counter1}
    );
 
    if (!t0) {
        Logger::Error("KDF3: KeyedHash256 failed computing T0");
        return std::nullopt;
    }
 
    // T1 = BLAKE3_keyed(key=PRK, data=T0 || 0x02)
    std::array<std::uint8_t, 33> t0_counter2{};
    std::copy(t0->begin(), t0->end(), t0_counter2.begin());
    t0_counter2[32] = 0x02;
 
    auto t1 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{t0_counter2}
    );
 
    if (!t1) {
        Logger::Error("KDF3: KeyedHash256 failed computing T1");
        return std::nullopt;
    }
 
    // T2 = BLAKE3_keyed(key=PRK, data=T1 || 0x03)
    std::array<std::uint8_t, 33> t1_counter3{};
    std::copy(t1->begin(), t1->end(), t1_counter3.begin());
    t1_counter3[32] = 0x03;
 
    auto t2 = KeyedHash256(
        std::span<const std::uint8_t, 32>{*prk},
        ConstByteSpan{t1_counter3}
    );
 
    if (!t2) {
        Logger::Error("KDF3: KeyedHash256 failed computing T2");
        return std::nullopt;
    }
 
    return std::make_tuple(*t0, *t1, *t2);
}

auto MixKey(Blake3Hash& chaining_key, ConstByteSpan input) -> bool {
    // C = KDF1(C, input)
    auto result = KDF1(chaining_key, input);
    if (!result) {
        Logger::Warning("MixKey: Failed to generate result");
        return false;
    }

    chaining_key = *result;
    return true;
}

auto EncryptAndHash(Blake3Hash& hash, const Blake3Hash& key, ConstByteSpan plaintext) -> std::optional<std::vector<std::uint8_t>> {
    namespace aead = core::cryptography::chacha20_poly1305;

    // Nonce is always zero — handshake AEAD keys are single-use.
    constexpr aead::Nonce kZeroNonce{};

    // Reinterpret the 32-byte Blake3Hash as a ChaCha20-Poly1305 key.
    aead::Key aead_key{};
    std::copy(key.begin(), key.end(), aead_key.begin());

    auto result = aead::Encrypt(plaintext, aead_key, kZeroNonce, ConstByteSpan{hash});
    if (!result) {
        Logger::Error("EncryptAndHash: AEAD encryption failed");
        return std::nullopt;
    }

    // Pack ciphertext || tag into a single buffer.
    std::vector<std::uint8_t> ct_with_tag;
    ct_with_tag.reserve(result->ciphertext.size() + result->tag.size());
    ct_with_tag.insert(ct_with_tag.end(), result->ciphertext.begin(), result->ciphertext.end());
    ct_with_tag.insert(ct_with_tag.end(), result->tag.begin(), result->tag.end());

    // H = HASH(H || ct || tag)
    MixHash(hash, ConstByteSpan{ct_with_tag});

    return ct_with_tag;
}

auto DecryptAndHash(Blake3Hash& hash, const Blake3Hash& key, ConstByteSpan ciphertext_with_tag) -> std::optional<std::vector<std::uint8_t>> {
    namespace aead = core::cryptography::chacha20_poly1305;

    if (ciphertext_with_tag.size() < aead::kTagBytes) {
        Logger::Error("DecryptAndHash: input too short for tag");
        return std::nullopt;
    }

    constexpr aead::Nonce kZeroNonce{};

    aead::Key aead_key{};
    std::copy(key.begin(), key.end(), aead_key.begin());

    // Split ciphertext and tag.
    const auto ct_len = ciphertext_with_tag.size() - aead::kTagBytes;
    auto ct_span = ciphertext_with_tag.subspan(0, ct_len);

    aead::Tag tag{};
    std::copy_n(ciphertext_with_tag.data() + ct_len, aead::kTagBytes, tag.begin());

    // Decrypt - AAD is the CURRENT hash (before MixHash).
    auto plaintext = aead::Decrypt(ct_span, tag, aead_key, kZeroNonce, ConstByteSpan{hash});
    if (!plaintext) {
        // Authentication failed - do NOT modify hash. Abort.
        
        return std::nullopt;
    }

    // Only on success: H = HASH(H || ct || tag)
    MixHash(hash, ciphertext_with_tag);

    return plaintext;
}

} // namespace core::handshake