#include "chacha20_poly1305.hpp"
#include "logger.hpp"

#include <openssl/rand.h>

using core::utils::Logger;

namespace core::cryptography::chacha20_poly1305 {

    auto Encrypt(std::span<const std::uint8_t> plaintext, const Key& key, const Nonce& nonce, std::span<const std::uint8_t> aad) 
    -> std::optional<EncryptResult> { 

        EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            Logger::Error("ChaCha20-Poly1305: Failed to create cipher context");
            return std::nullopt;
        }

        if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0) {
            Logger::Error("ChaCha20-Poly1305: EVP_EncryptInit_ex failed for cipher setup");
            return std::nullopt;
        }

        // Explicitly set nonce length to 12 bytes
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to set nonce length");
            return std::nullopt;
        }

        // Set key and nonce
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to set key and nonce");
            return std::nullopt;
        }

        // Process AAD if provided
        if (!aad.empty()) {
            int aad_len = 0;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(), static_cast<int>(aad.size())) <= 0) {
                Logger::Error("ChaCha20-Poly1305: Failed to process AAD");
                return std::nullopt;
            }
        }

        // Encrypt the plain text
        std::vector<std::uint8_t> ciphertext(plaintext.size());
        int out_len = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Encryption failed during update");
            return std::nullopt;
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Encryption failed during finalization");
            return std::nullopt;
        }

        ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

        // Extract the Poly1305 authentication tag
        Tag tag{};
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagBytes), tag.data()) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to extract authentication tag");
            return std::nullopt;
        }

        return EncryptResult{
            .ciphertext = std::move(ciphertext),
            .tag = tag
        };
    }

    auto Decrypt(std::span<const std::uint8_t> ciphertext, const Tag& tag, const Key& key, const Nonce& nonce, std::span<const std::uint8_t> aad) 
    -> std::optional<std::vector<std::uint8_t>> { 

        EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            Logger::Error("ChaCha20-Poly1305: Failed to create cipher context");
            return std::nullopt;
        }

        if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) <= 0) {
            Logger::Error("ChaCha20-Poly1305: EVP_DecryptInit_ex failed for cipher setup");
            return std::nullopt;
        }

        // Set nonce length
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to set nonce length");
            return std::nullopt;
        }

        // Set key and nonce
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to set key and nonce");
            return std::nullopt;
        }

        // Process AAD if provided
        if (!aad.empty()) {
            int aad_len = 0;
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(), static_cast<int>(aad.size())) <= 0) {
                Logger::Error("ChaCha20-Poly1305: Failed to process AAD");
                return std::nullopt;
            }
        }

        // Decrypt ciphertext
        std::vector<std::uint8_t> plaintext(ciphertext.size());
        int out_len = 0;

        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Decryption failed during update");
            return std::nullopt;
        }

        // Set the expected tag BEFORE finalize
        // EVP_CTRL_AEAD_SET_TAG expects a non-const pointer, hence the const_cast
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagBytes), const_cast<std::uint8_t*>(tag.data())) <= 0) {
            Logger::Error("ChaCha20-Poly1305: Failed to set expected authentication tag");
            return std::nullopt;
        }

        // Finalize and verify authentication tag
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &final_len) <= 0) {
            // Authentication failed, ciphertext was tampered with
            Logger::Error("ChaCha20-Poly1305: Authentication tag verification failed, ciphertext may be tampered");
            return std::nullopt;
        }

        plaintext.resize(static_cast<std::size_t>(out_len + final_len));
        return plaintext;
    }



    std::optional<Key> GenerateKey() { 
        Key key{};
        if (RAND_bytes(key.data(), static_cast<int>(kKeyBytes)) != 1) {
            Logger::Error("ChaCha20-Poly1305: Failed to generate random key");
            return std::nullopt;
        } 
        return key;
    }
    
    std::optional<Nonce> GenerateNonce() { 
        Nonce nonce{};
        if (RAND_bytes(nonce.data(), static_cast<int>(kNonceBytes)) != 1) {
            Logger::Error("ChaCha20-Poly1305: Failed to generate random nonce");
            return std::nullopt;
        }
        return nonce;
    }


} // namespace core::cryptography::chacha20_poly1305