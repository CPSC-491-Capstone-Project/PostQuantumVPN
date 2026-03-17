#include "x25519.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <cstring>

namespace core::cryptography::x25519 {

    namespace {

        // Build an EVP_PKEY from a raw 32-byte private key.
        // Returns nullptr on failure.
        EvpPkeyPtr PkeyFromPrivateBytes(const PrivateKey& private_key) {
            EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519,
                nullptr,
                private_key.data(),
                kPrivateKeyBytes
            );
            return EvpPkeyPtr{pkey};
        }

        // Build an EVP_PKEY from a raw 32-byte public key.
        // Returns nullptr on failure.
        EvpPkeyPtr PkeyFromPublicBytes(const PublicKey& public_key) {
            EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X25519,
                nullptr,
                public_key.data(),
                kPublicKeyBytes
            );
            return EvpPkeyPtr{pkey};
        }

    } // anonymous namespace

    auto GenerateKeyPair() -> std::optional<KeyPair> {
        // Create a keygen context for X25519
        EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr)};
        if (!ctx) {
            // TODO: Log Error
            return std::nullopt;
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Generate key pair
        EVP_PKEY* pkey_raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }
        EvpPkeyPtr pkey{pkey_raw};

        // Extract raw private key bytes
        KeyPair kp{};
        std::size_t priv_len = kPrivateKeyBytes;
        if (EVP_PKEY_get_raw_private_key(pkey.get(), kp.private_key.data(), &priv_len) != 1) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Extract raw public key bytes
        std::size_t pub_len = kPublicKeyBytes;
        if (EVP_PKEY_get_raw_public_key(pkey.get(), kp.public_key.data(), &pub_len) != 1) {
            // TODO: Log Error
            return std::nullopt;
        }

        return kp;
    }

    auto DeriveSharedSecret(
        const PrivateKey& private_key,
        const PublicKey&  peer_public_key
    ) -> std::optional<SharedSecret> {

        // Reconstruct our private key EVP_PKEY
        EvpPkeyPtr our_pkey = PkeyFromPrivateBytes(private_key);
        if (!our_pkey) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Reconstruct peer public key EVP_PKEY
        EvpPkeyPtr peer_pkey = PkeyFromPublicBytes(peer_public_key);
        if (!peer_pkey) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Create ECDH derive context
        EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new(our_pkey.get(), nullptr)};
        if (!ctx) {
            // TODO: Log Error
            return std::nullopt;
        }

        if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get()) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Determine output length (should be 32 for X25519)
        std::size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        if (secret_len != kSharedSecretBytes) {
            // TODO: Log Error
            return std::nullopt;
        }

        SharedSecret secret{};
        if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        return secret;
    }

    auto PublicKeyFromPrivate(const PrivateKey& private_key) -> std::optional<PublicKey> {
        EvpPkeyPtr pkey = PkeyFromPrivateBytes(private_key);
        if (!pkey) {
            // TODO: Log Error
            return std::nullopt;
        }

        PublicKey pub{};
        std::size_t pub_len = kPublicKeyBytes;
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) != 1) {
            // TODO: Log Error
            return std::nullopt;
        }

        return pub;
    }

} // namespace core::cryptography::x25519