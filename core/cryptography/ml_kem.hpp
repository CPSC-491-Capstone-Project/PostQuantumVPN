#ifndef _PQVPN_CORE_CRYPTOGRAPHY_ML_KEM_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_ML_KEM_HPP_

#include "evp_utils.hpp"

#include <cstdint>
#include <memory>
#include <vector>
#include <optional>
#include <span>

#include <openssl/evp.h>
#include <openssl/err.h>

// Previously called Kyber

namespace core::cryptography::ml_kem {

    enum class ParameterSet {
        ML_KEM_512, // NIST Security Level 1
        ML_KEM_768, // NIST Security Level 3 (default)
        ML_KEM_1024 // NIST Security Level 5
    };

    [[nodiscard]] constexpr const char* ParameterSetName(ParameterSet param) noexcept {
        switch (param) {
            case ParameterSet::ML_KEM_512:  return "ML-KEM-512";
            case ParameterSet::ML_KEM_768:  return "ML-KEM-768";
            case ParameterSet::ML_KEM_1024: return "ML-KEM-1024";
            default: return "ML-KEM-768";
        }
    }

    inline constexpr std::size_t kSharedSecretBytes = 32;

    using core::cryptography::EvpPkeyDeleter;
    using core::cryptography::EvpPkeyCtxDeleter;
    using core::cryptography::EvpPkeyPtr;
    using core::cryptography::EvpPkeyCtxPtr;

    // Key pair
    struct KeyPair {
        EvpPkeyPtr pkey; // OpenSSL key object (private + public)
        std::vector<std::uint8_t> public_key; // raw encapsulation key
    };

    // Encapsulation result
    struct EncapsulationResult {
        std::vector<std::uint8_t> ciphertext; // to be sent to the key holder
        std::vector<std::uint8_t> shared_secret; // 32-byte shared secret
    };

    // Core functions
    // All functions return a std::optional -> std::nullopt on failure
    // Errors are reported to the logger

    auto GenerateKeyPair(ParameterSet ps = ParameterSet::ML_KEM_768) -> std::optional<KeyPair>;
    auto Encapsulate(std::span<const std::uint8_t> public_key, ParameterSet ps = ParameterSet::ML_KEM_768) -> std::optional<EncapsulationResult>;
    auto Decapsulate(const EVP_PKEY* private_key, std::span<const std::uint8_t> ciphertext) -> std::optional<std::vector<std::uint8_t>>;
    auto ExtractPublicKey(const EVP_PKEY* pkey) -> std::optional<std::vector<std::uint8_t>>;

    inline auto Decapsulate(const KeyPair& kp, std::span<const std::uint8_t> ciphertext) {
        return Decapsulate(kp.pkey.get(), ciphertext);
    }
} // namespace core::cryptography::ml_kem


#endif // _PQVPN_CORE_CRYPTOGRAPHY_ML_KEM_HPP_