#ifndef _PQVPN_CORE_CRYPTOGRAPHY_X25519_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_X25519_HPP_

#include <cstdint>
#include <array>
#include <vector>
#include <optional>
#include <span>
#include <memory>

#include <openssl/evp.h>

namespace core::cryptography::x25519 {

    inline constexpr std::size_t kPrivateKeyBytes = 32; // 256-bit private key
    inline constexpr std::size_t kPublicKeyBytes  = 32; // 256-bit public key
    inline constexpr std::size_t kSharedSecretBytes = 32; // 256-bit shared secret

    using PrivateKey   = std::array<std::uint8_t, kPrivateKeyBytes>;
    using PublicKey    = std::array<std::uint8_t, kPublicKeyBytes>;
    using SharedSecret = std::array<std::uint8_t, kSharedSecretBytes>;

    // RAII deleter for EVP_PKEY
    struct EvpPkeyDeleter {
        void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    };

    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

    // RAII deleter for EVP_PKEY_CTX
    struct EvpPkeyCtxDeleter {
        void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    };

    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

    struct KeyPair {
        PrivateKey private_key;
        PublicKey  public_key;
    };

    // Core functions
    // All functions return std::optional -> std::nullopt on failure

    /// Generate a random X25519 key pair
    [[nodiscard]] auto GenerateKeyPair() -> std::optional<KeyPair>;

    /// Derive a shared secret from our private key and the peer's public key
    [[nodiscard]] auto DeriveSharedSecret(
        const PrivateKey& private_key,
        const PublicKey&  peer_public_key
    ) -> std::optional<SharedSecret>;

    /// Compute the public key from a private key
    [[nodiscard]] auto PublicKeyFromPrivate(
        const PrivateKey& private_key
    ) -> std::optional<PublicKey>;

} // namespace core::cryptography::x25519

#endif // _PQVPN_CORE_CRYPTOGRAPHY_X25519_HPP_