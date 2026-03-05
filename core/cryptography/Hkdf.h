#pragma once
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <vector>
#include <string>

// Wrapper around OpenSSL's HKDF implementation
class Hkdf {
public:

    // Extract phase - takes raw key material and salt, produces a pseudorandom key
    static std::vector<unsigned char> extract(
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& inputKeyMaterial)
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, inputKeyMaterial.data(), inputKeyMaterial.size());

        size_t outLen = 32;
        std::vector<unsigned char> pseudorandomKey(outLen);
        EVP_PKEY_derive(ctx, pseudorandomKey.data(), &outLen);

        EVP_PKEY_CTX_free(ctx);
        return pseudorandomKey;
    }

    // Expand phase - takes the pseudorandom key and info, produces the final key
    static std::vector<unsigned char> expand(
        const std::vector<unsigned char>& pseudorandomKey,
        const std::vector<unsigned char>& info,
        size_t outputLen)
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, pseudorandomKey.data(), pseudorandomKey.size());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size());

        std::vector<unsigned char> outputKey(outputLen);
        EVP_PKEY_derive(ctx, outputKey.data(), &outputLen);

        EVP_PKEY_CTX_free(ctx);
        return outputKey;
    }

    // Derives a key by running extract then expand together
    static std::vector<unsigned char> deriveKey(
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& inputKeyMaterial,
        const std::vector<unsigned char>& info,
        size_t outputLen)
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, inputKeyMaterial.data(), inputKeyMaterial.size());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size());

        std::vector<unsigned char> outputKey(outputLen);
        EVP_PKEY_derive(ctx, outputKey.data(), &outputLen);

        EVP_PKEY_CTX_free(ctx);
        return outputKey;
    }
};