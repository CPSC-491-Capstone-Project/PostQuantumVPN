#include "hkdf.hpp"
#include "logger.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

using core::utils::Logger;

namespace core::cryptography::hkdf {

    auto Extract(
        const std::vector<std::uint8_t>& salt,
        const std::vector<std::uint8_t>& inputKeyMaterial
    ) -> std::optional<std::vector<std::uint8_t>>
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) {
            Logger::Error("HKDF: Failed to create EVP_PKEY_CTX");
            return std::nullopt;
        }

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            Logger::Error("HKDF: Extract derive init failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size()));
        EVP_PKEY_CTX_set1_hkdf_key(ctx, inputKeyMaterial.data(), static_cast<int>(inputKeyMaterial.size()));

        std::size_t outLen = 32;
        std::vector<std::uint8_t> pseudorandomKey(outLen);

        if (EVP_PKEY_derive(ctx, pseudorandomKey.data(), &outLen) <= 0) {
            Logger::Error("HKDF: Extract derive failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_free(ctx);
        return pseudorandomKey;
    }

    // Expand phase - takes the pseudorandom key and info string, stretches into output key material
    // of requested length. Info string binds the key to a specific context to prevent reuse.
    auto Expand(
        const std::vector<std::uint8_t>& pseudorandomKey,
        const std::vector<std::uint8_t>& info,
        std::size_t outputLen
    ) -> std::optional<std::vector<std::uint8_t>>
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) {
            Logger::Error("HKDF: Failed to create EVP_PKEY_CTX");
            return std::nullopt;
        }

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            Logger::Error("HKDF: Expand derive init failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, pseudorandomKey.data(), static_cast<int>(pseudorandomKey.size()));
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size()));

        std::vector<std::uint8_t> outputKey(outputLen);

        if (EVP_PKEY_derive(ctx, outputKey.data(), &outputLen) <= 0) {
            Logger::Error("HKDF: Expand derive failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_free(ctx);
        return outputKey;
    }

    auto DeriveKey(
        const std::vector<std::uint8_t>& salt,
        const std::vector<std::uint8_t>& inputKeyMaterial,
        const std::vector<std::uint8_t>& info,
        std::size_t outputLen
    ) -> std::optional<std::vector<std::uint8_t>>
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) {
            Logger::Error("HKDF: Failed to create EVP_PKEY_CTX");
            return std::nullopt;
        }

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            Logger::Error("HKDF: DeriveKey derive init failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size()));
        EVP_PKEY_CTX_set1_hkdf_key(ctx, inputKeyMaterial.data(), static_cast<int>(inputKeyMaterial.size()));
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size()));

        std::vector<std::uint8_t> outputKey(outputLen);

        if (EVP_PKEY_derive(ctx, outputKey.data(), &outputLen) <= 0) {
            Logger::Error("HKDF: DeriveKey derive failed");
            EVP_PKEY_CTX_free(ctx);
            return std::nullopt;
        }

        EVP_PKEY_CTX_free(ctx);
        return outputKey;
    }

} // namespace core::cryptography::hkdf