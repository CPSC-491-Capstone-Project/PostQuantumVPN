#ifndef _PQVPN_CORE_CRYPTOGRAPHY_CHACHA20_POLY1305_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_CHACHA20_POLY1305_HPP_

#include <cstdint>
#include <array>
#include <vector>
#include <optional>
#include <span>
#include <memory>

#include <openssl/evp.h>

namespace core::cryptography::chacha20_poly1305 {

    inline constexpr std::size_t kKeyBytes = 32; // 256-bit key
    inline constexpr std::size_t kNonceBytes = 12; // 96-bit nonce (IV)
    inline constexpr std::size_t kTagBytes = 16; // 128-bit authentication tag

    using Key = std::array<std::uint8_t, kKeyBytes>;
    using Nonce = std::array<std::uint8_t, kNonceBytes>;
    using Tag = std::array<std::uint8_t, kTagBytes>;

    // RAII deleter for EVP_CIPHER_CTX
    struct EvpCipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
    };

    using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

    struct EncryptResult {
        std::vector<std::uint8_t> ciphertext; // same length as plaintext
        Tag tag; // 16-byte Poly1305 auth tag
    };

    // Core functions
    // All functions return std::optional -> std::nullopt on failure

    [[nodiscard]] auto Encrypt(
        std::span<const std::uint8_t> plaintext,
        const Key& key,
        const Nonce& nonce,
        std::span<const std::uint8_t> aad = {}
    ) -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto Decrypt(
        std::span<const std::uint8_t> ciphertext,
        const Tag& tag,
        const Key& key,
        const Nonce& nonce,
        std::span<const std::uint8_t> aad = {}
    ) -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto GenerateKey() -> std::optional<Key>;
    
    [[nodiscard]] auto GenerateNonce() -> std::optional<Nonce>;

} // namespace core::cryptography::chacha20_poly1305

#endif // _PQVPN_CORE_CRYPTOGRAPHY_CHACHA20_POLY1305_HPP_