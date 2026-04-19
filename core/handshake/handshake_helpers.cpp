#include "handshake_helpers.hpp"
#include "logger.hpp"
#include "chacha20_poly1305.hpp"
#include "secure_memory.hpp"
#include "udp_socket.hpp"
#include "random.hpp"

#include <tuple>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

using core::utils::Logger;
using core::utils::ct_memcmp;
using core::utils::secure_zero;
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

    // PRK is consumed — zero it before any return path.
    secure_zero(*prk);

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
        secure_zero(*prk);
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

    // PRK and the T0||counter buffer are consumed — zero them before any return path.
    secure_zero(*prk);
    secure_zero(t0_counter2);

    if (!t1) {
        Logger::Error("KDF2: KeyedHash256 failed computing T1");
        return std::nullopt;
    }

    return std::make_tuple(*t0, *t1);
}

auto KDF3(const Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<std::tuple<Blake3Hash, Blake3Hash, Blake3Hash>> {
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
        secure_zero(*prk);
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
        secure_zero(*prk);
        secure_zero(t0_counter2);
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

    // All intermediates consumed — zero them before any return path.
    secure_zero(*prk);
    secure_zero(t0_counter2);
    secure_zero(t1_counter3);

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

    // Zero the local key copy — it is no longer needed.
    secure_zero(aead_key);

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

    // Zero local key and tag copies — they are no longer needed.
    secure_zero(aead_key);
    secure_zero(tag);

    if (!plaintext) {
        // Authentication failed - do NOT modify hash. Abort.
        return std::nullopt;
    }

    // Only on success: H = HASH(H || ct || tag)
    MixHash(hash, ciphertext_with_tag);

    return plaintext;
}

auto DeriveMac1Key(ConstByteSpan responder_static_pub) -> std::optional<Blake3Hash> {
    // Build input: "mac1----" || responder_static_x25519_pub
    std::vector<std::uint8_t> input;
    input.reserve(kLabelMac1.size() + responder_static_pub.size());

    for (auto c : kLabelMac1)
        input.push_back(static_cast<std::uint8_t>(c));
    for (auto b : responder_static_pub)
        input.push_back(b);

    auto result = Hash256(ConstByteSpan{input.data(), input.size()});
    if (!result) {
        Logger::Error("Handshake: DeriveMac1Key failed");
        return std::nullopt;
    }

    return result;
}

auto ComputeMac1(
    const Blake3Hash& mac1_key,
    ConstByteSpan message_before_mac1
) -> std::optional<std::array<std::uint8_t, 16>>
{
    auto hash = KeyedHash256(
        std::span<const std::uint8_t, 32>(mac1_key.data(), 32),
        message_before_mac1
    );

    if (!hash) {
        Logger::Error("Handshake: ComputeMac1 failed");
        return std::nullopt;
    }

    // Truncate to 16 bytes
    std::array<std::uint8_t, 16> mac1;
    std::memcpy(mac1.data(), hash->data(), 16);
    return mac1;
}

auto VerifyMac1(
    const Blake3Hash& mac1_key,
    ConstByteSpan message_before_mac1,
    std::span<const std::uint8_t, 16> received_mac1
) -> bool
{
    auto expected = ComputeMac1(mac1_key, message_before_mac1);
    if (!expected) {
        Logger::Error("Handshake: VerifyMac1 failed to compute expected MAC");
        return false;
    }

    bool equal = ct_memcmp(expected->data(), received_mac1.data(), 16);
    secure_zero(*expected);
    return equal;
}

auto DeriveCookieKey(ConstByteSpan static_x25519_pub) -> std::optional<Blake3Hash> {
    // Build input: "cookie--" || static_x25519_pub
    std::vector<std::uint8_t> input;
    input.reserve(kLabelCookie.size() + static_x25519_pub.size());

    for (auto c : kLabelCookie)
        input.push_back(static_cast<std::uint8_t>(c));
    for (auto b : static_x25519_pub)
        input.push_back(b);

    auto result = Hash256(ConstByteSpan{input.data(), input.size()});
    if (!result) {
        Logger::Error("Handshake: DeriveCookieKey failed");
        return std::nullopt;
    }

    return result;
}

auto GenerateCookie(
    const RotatingSecret& rotating_secret,
    const std::string& sender_ip,
    std::uint16_t sender_port
) -> std::optional<Cookie>
{
    // Build sender_ip_bytes || port
    std::vector<std::uint8_t> data;

    // Try IPv4 first
    struct in_addr ipv4{};
    struct in6_addr ipv6{};

    if (inet_pton(AF_INET, sender_ip.c_str(), &ipv4) == 1) {
        // IPv4: 4 bytes IP + 2 bytes port
        data.resize(6);
        std::memcpy(data.data(), &ipv4, 4);
        data[4] = static_cast<std::uint8_t>(sender_port >> 8);
        data[5] = static_cast<std::uint8_t>(sender_port & 0xFF);
    } else if (inet_pton(AF_INET6, sender_ip.c_str(), &ipv6) == 1) {
        // IPv6: first 8 bytes (/64 prefix) + 2 bytes port
        data.resize(10);
        std::memcpy(data.data(), &ipv6, 8);
        data[8] = static_cast<std::uint8_t>(sender_port >> 8);
        data[9] = static_cast<std::uint8_t>(sender_port & 0xFF);
    } else {
        Logger::Error("Handshake: GenerateCookie invalid IP address");
        return std::nullopt;
    }

    // cookie = BLAKE3-128(key=rotating_secret, data=sender_ip_bytes)
    auto hash = KeyedHash256(
        std::span<const std::uint8_t, 32>(rotating_secret.data(), 32),
        ConstByteSpan{data.data(), data.size()}
    );

    if (!hash) {
        Logger::Error("Handshake: GenerateCookie BLAKE3 failed");
        return std::nullopt;
    }

    // Truncate to 16 bytes
    Cookie cookie;
    std::memcpy(cookie.data(), hash->data(), 16);
    return cookie;
}

auto BuildCookieReply(
    std::uint32_t receiver_index,
    const Cookie& cookie,
    const Blake3Hash& cookie_key,
    std::span<const std::uint8_t, 16> mac1
) -> std::optional<CookieReply>
{
    namespace aead = core::cryptography::chacha20_poly1305;

    // Generate random 12-byte nonce
    auto nonce_opt = aead::GenerateNonce();
    if (!nonce_opt) {
        Logger::Error("Handshake: BuildCookieReply failed to generate nonce");
        return std::nullopt;
    }

    // Reinterpret cookie_key as ChaCha20 key
    aead::Key aead_key{};
    std::copy(cookie_key.begin(), cookie_key.end(), aead_key.begin());

    // Encrypt cookie with mac1 as AAD
    auto result = aead::Encrypt(
        ConstByteSpan{cookie.data(), cookie.size()},
        aead_key,
        *nonce_opt,
        ConstByteSpan{mac1.data(), mac1.size()}
    );

    if (!result) {
        Logger::Error("Handshake: BuildCookieReply encryption failed");
        return std::nullopt;
    }

    CookieReply reply;
    reply.receiver_index = receiver_index;
    reply.nonce = *nonce_opt;

    // Pack ciphertext || tag into encrypted_cookie
    std::memcpy(reply.encrypted_cookie.data(), result->ciphertext.data(), 16);
    std::memcpy(reply.encrypted_cookie.data() + 16, result->tag.data(), 16);

    return reply;
}

auto DecryptCookieReply(
    const CookieReply& reply,
    const Blake3Hash& cookie_key,
    std::span<const std::uint8_t, 16> last_mac1_sent
) -> std::optional<Cookie>
{
    namespace aead = core::cryptography::chacha20_poly1305;

    aead::Key aead_key{};
    std::copy(cookie_key.begin(), cookie_key.end(), aead_key.begin());

    // Split ciphertext and tag from encrypted_cookie
    ConstByteSpan ct{reply.encrypted_cookie.data(), 16};
    aead::Tag tag{};
    std::memcpy(tag.data(), reply.encrypted_cookie.data() + 16, 16);

    auto plaintext = aead::Decrypt(
        ct,
        tag,
        aead_key,
        reply.nonce,
        ConstByteSpan{last_mac1_sent.data(), last_mac1_sent.size()}
    );

    if (!plaintext) {
        Logger::Error("Handshake: DecryptCookieReply decryption failed");
        return std::nullopt;
    }

    Cookie cookie;
    std::memcpy(cookie.data(), plaintext->data(), 16);
    return cookie;
}

auto ComputeMac2(
    const Cookie& cookie,
    ConstByteSpan message_before_mac2
) -> std::optional<std::array<std::uint8_t, 16>>
{
    // mac2 = BLAKE3-128(key=cookie, data=message_bytes_before_mac2)
    auto hash = KeyedHash256(
        std::span<const std::uint8_t, 32>(
            // Pad cookie to 32 bytes for BLAKE3 key
            [&]() -> std::array<std::uint8_t, 32> {
                std::array<std::uint8_t, 32> key{};
                std::memcpy(key.data(), cookie.data(), 16);
                return key;
            }().data(), 32),
        message_before_mac2
    );

    if (!hash) {
        Logger::Error("Handshake: ComputeMac2 failed");
        return std::nullopt;
    }

    std::array<std::uint8_t, 16> mac2;
    std::memcpy(mac2.data(), hash->data(), 16);
    return mac2;
}

auto VerifyMac2(
    const Cookie& cookie,
    ConstByteSpan message_before_mac2,
    std::span<const std::uint8_t, 16> received_mac2
) -> bool
{
    auto expected = ComputeMac2(cookie, message_before_mac2);
    if (!expected) {
        Logger::Error("Handshake: VerifyMac2 failed to compute expected MAC");
        return false;
    }

    bool equal = ct_memcmp(expected->data(), received_mac2.data(), 16);
    secure_zero(*expected);
    return equal;
}

} // namespace core::handshake
