#ifndef _PQVPN_CORE_CRYPTOGRAPHY_HKDF_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_HKDF_HPP_

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <vector>
#include <optional>
#include <cstdint>

namespace core::cryptography::hkdf {

    // Wrapper around OpenSSL's HKDF implementation
    // All functions return std::nullopt on failure
    // Errors are reported to the logger

    [[nodiscard]] auto Extract(
        const std::vector<std::uint8_t>& salt,
        const std::vector<std::uint8_t>& inputKeyMaterial
    ) -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto Expand(
        const std::vector<std::uint8_t>& pseudorandomKey,
        const std::vector<std::uint8_t>& info,
        std::size_t outputLen
    ) -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto DeriveKey(
        const std::vector<std::uint8_t>& salt,
        const std::vector<std::uint8_t>& inputKeyMaterial,
        const std::vector<std::uint8_t>& info,
        std::size_t outputLen
    ) -> std::optional<std::vector<std::uint8_t>>;

} // namespace core::cryptography::hkdf

#endif // _PQVPN_CORE_CRYPTOGRAPHY_HKDF_HPP_