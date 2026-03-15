#include "ml_kem.hpp"
#include "logger.hpp"

#include <openssl/core_names.h>
#include <openssl/params.h>

using core::utils::Logger;

// previously called Kyber

namespace core::cryptography::ml_kem {

    // Internal helpers
    namespace {
        auto PkeyFromPublicBytes(std::span<const std::uint8_t> data, ParameterSet ps)
        -> std::optional<EvpPkeyPtr> {

            const auto* name = ParameterSetName(ps);
            EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, name, nullptr)};

            if (!ctx) {
                Logger::Error("ML-KEM: EVP_PKEY_CTX_new_from_name failed -- ensure OpenSSL >= 3.5");
                // Chances are the OpenSSL build is not >= 3.5
                return std::nullopt;
            }

            if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
                Logger::Error("ML-KEM: EVP_PKEY_fromdata_init failed -- OpenSSL internals error or invalid ParameterSet");
                return std::nullopt;
            }

            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                const_cast<std::uint8_t*>(data.data()),
                data.size());
            params[1] = OSSL_PARAM_construct_end();

            EVP_PKEY* raw = nullptr;
            if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !raw) {
                Logger::Error("ML-KEM: EVP_PKEY_fromdata failed -- public key import failed");
                return std::nullopt;
            }

            return EvpPkeyPtr{raw};
        }
    } // anonymous namespace

    auto ExtractPublicKey(const EVP_PKEY* pkey) -> std::optional<std::vector<std::uint8_t>> {
        if (!pkey) {
            Logger::Error("ML-KEM: ExtractPublicKey called with null EVP_PKEY");
            return std::nullopt;
        }

        std::size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len) <= 0) {
            Logger::Error("ML-KEM: Failed to query public key length");
            return std::nullopt;
        }

        std::vector<std::uint8_t> buf(len);
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf.data(), buf.size(), &len) <= 0) {
            Logger::Error("ML-KEM: Failed to extract public key bytes");
        } 
        
        buf.resize(len);
        return buf;
    }

    auto GenerateKeyPair(ParameterSet ps) -> std::optional<KeyPair> {
        const auto* name = ParameterSetName(ps);

        EvpPkeyPtr pkey{EVP_PKEY_Q_keygen(nullptr, nullptr, name)};
        if (!pkey) {
            Logger::Error("ML-KEM: Key generation failed for " + std::string(name));
            return std::nullopt;
        }

        auto pub = ExtractPublicKey(pkey.get());
        if (!pub) {
            Logger::Error("ML-KEM: Failed to extract public key after key generation");
            return std::nullopt;
        }

        return KeyPair {
            .pkey = std::move(pkey),
            .public_key = std::move(*pub)
        };
    }

    auto Encapsulate(std::span<const std::uint8_t> public_key, ParameterSet ps) -> std::optional<EncapsulationResult> {
        // const auto* name = ParameterSetName(ps);

        if (public_key.empty()) {
            Logger::Error("ML-KEM: Encapsulate called with empty public key");
            return std::nullopt;
        }

        auto peer = PkeyFromPublicBytes(public_key, ps);
        if (!peer) {
            Logger::Error("ML-KEM: Encapsulate failed to reconstruct peer public key");
            return std::nullopt;
        }

        EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, peer->get(), nullptr)};
        if (!ctx) {
            Logger::Error("ML-KEM: Encapsulate failed to create EVP_PKEY_CTX from peer key");
            return std::nullopt;
        }

        if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
            Logger::Error("ML-KEM: EVP_PKEY_encapsulate_init failed");
            return std::nullopt;
        }

        std::size_t ct_len = 0;
        std::size_t ss_len = 0;
        if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &ss_len) <= 0) {
            Logger::Error("ML-KEM: Failed to query encapsulation output lengths");
            return std::nullopt;
        }

        std::vector<std::uint8_t> ciphertext(ct_len);
        std::vector<std::uint8_t> shared_secret(ss_len);

        if (EVP_PKEY_encapsulate(ctx.get(), ciphertext.data(), &ct_len, shared_secret.data(), &ss_len) <= 0) {
            Logger::Error("ML-KEM: Encapsulation failed");
            return std::nullopt;
        }

        ciphertext.resize(ct_len);
        shared_secret.resize(ss_len);

        return EncapsulationResult {
            .ciphertext = std::move(ciphertext),
            .shared_secret = std::move(shared_secret)
        };
    }

    auto Decapsulate(const EVP_PKEY* private_key, std::span<const std::uint8_t> ciphertext) -> std::optional<std::vector<std::uint8_t>> {
        if (!private_key) {
            Logger::Error("ML-KEM: Decapsulate called with null private key");
            return std::nullopt;
        }

        if (ciphertext.empty()) {
            Logger::Info("ML-KEM: Decapsulate called with empty ciphertext");
            return std::nullopt;
        }

        EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY*>(private_key), nullptr)};
        if (!ctx) {
            Logger::Error("ML-KEM: Decapsulate failed to create EVP_PKEY_CTX from private key");
            return std::nullopt;
        }

        if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
            Logger::Error("ML-KEM: EVP_PKEY_decapsulate_init failed");
            return std::nullopt;
        }

        std::size_t ss_len = 0;
        if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &ss_len, const_cast<unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
            Logger::Error("ML-KEM: Failed to query decapsulation output length");
            return std::nullopt;
        }

        std::vector<std::uint8_t> shared_secret(ss_len);

        if (EVP_PKEY_decapsulate(ctx.get(), shared_secret.data(), &ss_len, const_cast<unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
            Logger::Error("ML-KEM: Decapsulation failed");
            return std::nullopt;
        }

        shared_secret.resize(ss_len);
        return shared_secret;
    }

} // namespace core::cryptography::ml_kem 