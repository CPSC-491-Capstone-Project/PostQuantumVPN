#ifndef _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_
#define _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_

#include "handshake_constants.hpp"
#include "blake3.hpp"
#include "bit_utils.hpp"

namespace core::handshake {
    
// ---------------------------------------------------------------------------
// Mac1Key
// ---------------------------------------------------------------------------
// Derives the mac1 key for a given static X25519 public key.
// mac1_key = BLAKE3-256("mac1----" || responder_static_x25519_pub)
// Can be precomputed once per peer.
// ---------------------------------------------------------------------------
[[nodiscard]] auto DeriveMac1Key(
    ConstByteSpan responder_static_pub
) -> std::optional<Blake3Hash>;

// ---------------------------------------------------------------------------
// ComputeMac1
// ---------------------------------------------------------------------------
// Computes mac1 over the message bytes before the mac1 field.
// mac1 = BLAKE3-keyed(mac1_key, message_bytes_before_mac1) truncated to 16 bytes
// ---------------------------------------------------------------------------
[[nodiscard]] auto ComputeMac1(
    const Blake3Hash& mac1_key,
    ConstByteSpan message_before_mac1
) -> std::optional<std::array<std::uint8_t, 16>>;

// ---------------------------------------------------------------------------
// VerifyMac1
// ---------------------------------------------------------------------------
// Verifies mac1 using constant time comparison.
// Returns false and should be dropped silently on mismatch.
// ---------------------------------------------------------------------------
[[nodiscard]] auto VerifyMac1(
    const Blake3Hash& mac1_key,
    ConstByteSpan message_before_mac1,
    std::span<const std::uint8_t, 16> received_mac1
) -> bool;

// ---------------------------------------------------------------------------
// Cookie constants
// ---------------------------------------------------------------------------
inline constexpr std::size_t kCookieBytes = 16;
inline constexpr std::size_t kRotatingSecretBytes = 32;
inline constexpr std::size_t kCookieNonceBytes = 12;

using Cookie = std::array<std::uint8_t, kCookieBytes>;
using RotatingSecret = std::array<std::uint8_t, kRotatingSecretBytes>;
using CookieNonce = std::array<std::uint8_t, kCookieNonceBytes>;

// ---------------------------------------------------------------------------
// Cookie Reply message struct (Type 3) — 64 bytes total
// ---------------------------------------------------------------------------
struct CookieReply {
    std::uint32_t type{3};
    std::uint32_t receiver_index{0};
    CookieNonce   nonce{};
    // 16 bytes cookie + 16 bytes Poly1305 tag = 32 bytes
    std::array<std::uint8_t, 32> encrypted_cookie{};
};

// ---------------------------------------------------------------------------
// DeriveCookieKey
// ---------------------------------------------------------------------------
// cookie_key = BLAKE3-256("cookie--" || static_x25519_pub)
// Can be precomputed once per peer.
// ---------------------------------------------------------------------------
[[nodiscard]] auto DeriveCookieKey(
    ConstByteSpan static_x25519_pub
) -> std::optional<Blake3Hash>;

// ---------------------------------------------------------------------------
// GenerateCookie
// ---------------------------------------------------------------------------
// Generates a 16-byte cookie for a specific sender IP and port.
// cookie = BLAKE3-128(key=rotating_secret, data=sender_ip_bytes || port)
// ---------------------------------------------------------------------------
[[nodiscard]] auto GenerateCookie(
    const RotatingSecret& rotating_secret,
    const std::string& sender_ip,
    std::uint16_t sender_port
) -> std::optional<Cookie>;

// ---------------------------------------------------------------------------
// BuildCookieReply
// ---------------------------------------------------------------------------
// Builds a Type 3 Cookie Reply message.
// Encrypts the cookie using ChaCha20-Poly1305 with mac1 as AAD.
// ---------------------------------------------------------------------------
[[nodiscard]] auto BuildCookieReply(
    std::uint32_t receiver_index,
    const Cookie& cookie,
    const Blake3Hash& cookie_key,
    std::span<const std::uint8_t, 16> mac1
) -> std::optional<CookieReply>;

// ---------------------------------------------------------------------------
// DecryptCookieReply
// ---------------------------------------------------------------------------
// Decrypts a Cookie Reply message and returns the 16-byte cookie.
// last_mac1_sent is the mac1 from the message that triggered the cookie reply.
// ---------------------------------------------------------------------------
[[nodiscard]] auto DecryptCookieReply(
    const CookieReply& reply,
    const Blake3Hash& cookie_key,
    std::span<const std::uint8_t, 16> last_mac1_sent
) -> std::optional<Cookie>;

// ---------------------------------------------------------------------------
// ComputeMac2
// ---------------------------------------------------------------------------
// mac2 = BLAKE3-128(key=cookie, data=message_bytes_before_mac2)
// If no valid cookie, returns 16 zero bytes.
// ---------------------------------------------------------------------------
[[nodiscard]] auto ComputeMac2(
    const Cookie& cookie,
    ConstByteSpan message_before_mac2
) -> std::optional<std::array<std::uint8_t, 16>>;

// ---------------------------------------------------------------------------
// VerifyMac2
// ---------------------------------------------------------------------------
// Verifies mac2 using constant time comparison.
// Only called when server is under load.
// ---------------------------------------------------------------------------
[[nodiscard]] auto VerifyMac2(
    const Cookie& cookie,
    ConstByteSpan message_before_mac2,
    std::span<const std::uint8_t, 16> received_mac2
) -> bool;

// ---------------------------------------------------------------------------
// MixHash
// ---------------------------------------------------------------------------
// H = HASH(H || data)
//
// Folds new material into the running transcript hash.
// Every piece of data that touches the wire gets mixed in so that
// both sides can verify they saw the same handshake.
// ---------------------------------------------------------------------------
 
void MixHash(Blake3Hash& hash, ConstByteSpan data);

// ---------------------------------------------------------------------------
// KDF1, KDF2, KDF3  (DG-230)
// ---------------------------------------------------------------------------
// WireGuard's KDF is built from HMAC-BLAKE2s.
// Ours uses BLAKE3's built-in keyed-hash mode (32-byte key).
//
//   HMAC(key, input) := BLAKE3_keyed(key, input)
//
//   temp = HMAC(C, input)
//   KDF1: output1 = HMAC(temp, 0x01)
//   KDF2: output1 = HMAC(temp, 0x01)
//         output2 = HMAC(temp, output1 || 0x02)
//   KDF3: output1 = HMAC(temp, 0x01)
//         output2 = HMAC(temp, output1 || 0x02)
//         output3 = HMAC(temp, output2 || 0x03)
//
// All return std::nullopt on internal failure.
// ---------------------------------------------------------------------------
 
[[nodiscard]] auto KDF1(const Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<Blake3Hash>;
[[nodiscard]] auto KDF2(const Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<std::tuple<Blake3Hash, Blake3Hash>>;
[[nodiscard]] auto KDF3(const Blake3Hash& chaining_key,ConstByteSpan input) -> std::optional<std::tuple<Blake3Hash, Blake3Hash, Blake3Hash>>;


// ---------------------------------------------------------------------------
// MixKey
// ---------------------------------------------------------------------------
// C = KDF1(C, input)
//
// Absorbs a shared secret (DH output, KEM shared secret, or raw
// public-key material) into the chaining key.  This is a "blind"
// ratchet — it does NOT produce an encryption key.
//
// When the handshake logic needs an encryption key after a DH/KEM
// operation, it calls KDF2 directly at the call site instead.
//
// The ordering of MixKey calls is what provides the hybrid security
// guarantee: if either the X25519 DH output or the ML-KEM shared
// secret is secure, the resulting chaining key remains unpredictable.
// ---------------------------------------------------------------------------
 
[[nodiscard]] auto MixKey(Blake3Hash& chaining_key, ConstByteSpan input) -> bool;

// ---------------------------------------------------------------------------
// EncryptAndHash / DecryptAndHash
// ---------------------------------------------------------------------------
// AEAD-encrypt plaintext under key k with nonce = 0 and
// additional data = H, then mix the ciphertext||tag into H.
//
// WireGuard equivalent: AEAD(k, counter=0, plain, H)
//   - key k comes from the most recent MixKey
//   - nonce is always 0 (single use per key)
//   - AAD is the current transcript hash H
//
// EncryptAndHash:
//   ct || tag = ChaCha20Poly1305_Encrypt(k, nonce=0, plain, H)
//   H = HASH(H || ct || tag)
//   returns ct || tag
//
// DecryptAndHash:
//   plain = ChaCha20Poly1305_Decrypt(k, nonce=0, ct_with_tag, H)
//   H = HASH(H || ct_with_tag)     (mix in BEFORE verifying — same as WG)
//   returns plain, or nullopt on auth failure
// ---------------------------------------------------------------------------

[[nodiscard]] auto EncryptAndHash(Blake3Hash& hash, const Blake3Hash& key, ConstByteSpan plaintext) -> std::optional<std::vector<std::uint8_t>>;
[[nodiscard]] auto DecryptAndHash(Blake3Hash& hash, const Blake3Hash& key, ConstByteSpan ciphertext_with_tag) -> std::optional<std::vector<std::uint8_t>>;

} // namespace core::handshake


#endif //_PQVPN_CORE_HANDSHAKE_HELPERS_HPP_