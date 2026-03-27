#ifndef _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_
#define _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_

#include "handshake_constants.hpp"
#include "blake3.hpp"
#include "bit_utils.hpp"

namespace core::handshake {

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
// C, k = KDF2(C, input)
//
// Ratchets the chaining key forward and produces a symmetric
// encryption key. After MixKey the caller can use k with
// EncryptAndHash / DecryptAndHash.
// ---------------------------------------------------------------------------
 
[[nodiscard]] auto MixKey(Blake3Hash& chaining_key, ConstByteSpan input) -> std::optional<Blake3Hash>;

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