#include "chacha20_poly1305.hpp"

#include <openssl/rand.h>

namespace core::cryptography::chacha20_poly1305 {

    auto Encrypt(std::span<const std::uint8_t> plaintext, const Key& key, const Nonce& nonce, std::span<const std::uint8_t> aad) 
    -> std::optional<EncryptResult> { 
        
        if (plaintext.empty()) {
            // TODO: Log Info
            return std::nullopt;
        }

        EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            // TODO: Log Error
            return std::nullopt;
        }

        if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Explicitly set nonce length to 12 bytes
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Set key and nonce
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        // Process AAD if provided
        if (!aad.empty()) {
            int aad_len = 0;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(), static_cast<int>(aad.size())) <= 0) {
                // TODO: Log Error
                return std::nullopt;
            }
        }

        // Encrypt the plain text
        std::vector<std::uint8_t> ciphertext(plaintext.size());
        int out_len = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

        // Extract the Poly1305 authentication tag
        Tag tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagBytes), tag.data()) <= 0) {
            // TODO: Log Error
            return std::nullopt;
        }

        return EncryptResult{
            .ciphertext = std::move(ciphertext),
            .tag = tag
        };
    }

    auto Decrypt(std::span<const std::uint8_t> ciphertext, const Tag& tag, const Key& key, const Nonce& nonce, std::span<const std::uint8_t> aad) 
    -> std::optional<std::vector<std::uint8_t>> { 
        return {}; 
    }

    std::optional<Key> GenerateKey() { 
        Key key{};
        if (RAND_bytes(key.data(), static_cast<int>(kKeyBytes)) != 1) {
            // TODO: Log Error
            return std::nullopt;
        } 
        return key;
    }
    
    std::optional<Nonce> GenerateNonce() { 
        Nonce nonce{};
        if (RAND_bytes(nonce.data(), static_cast<int>(kNonceBytes)) != 1) {
            // TODO: Log Error
            return std::nullopt;
        }
        return nonce;
    }


} // namespace core::cryptography::chacha20_poly1305