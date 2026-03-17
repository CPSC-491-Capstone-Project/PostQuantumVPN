#ifndef _PQVPN_CORE_CRYPTOGRAPHY_BLAKE3_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_BLAKE3_HPP_

#include <cstdint>
#include <array>
#include <vector>
#include <optional>
#include <span>

#include <blake3.h>

namespace core::cryptography::blake3 {

    inline constexpr std::size_t kDefaultHashBytes = BLAKE3_OUT_LEN; // 32 bytes (256-bit)

    using Hash = std::array<std::uint8_t, kDefaultHashBytes>;

    // Core functions
    // All functions return std::optional -> std::nullopt on failure

    /// Hash arbitrary input data, returning a fixed 32-byte digest
    [[nodiscard]] auto Hash256(
        std::span<const std::uint8_t> input
    ) -> std::optional<Hash>;

    /// Hash arbitrary input data into a caller-specified output length (XOF mode)
    /// output_len must be > 0
    [[nodiscard]] auto HashXof(
        std::span<const std::uint8_t> input,
        std::size_t output_len
    ) -> std::optional<std::vector<std::uint8_t>>;

} // namespace core::cryptography::blake3

#endif // _PQVPN_CORE_CRYPTOGRAPHY_BLAKE3_HPP_