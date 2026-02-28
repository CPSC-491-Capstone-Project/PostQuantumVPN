/*
 * C++23 implementation of all Keccak/SHA-3 instances from FIPS 202.
 *
 * Based on the reference implementation by the Keccak Team
 * (Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van Keer).
 * Original source placed in the public domain under CC0 1.0.
 * https://keccak.team/
 */

#ifndef _PQVPN_CORE_CRYPTOGRAPHY_SHA3_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_SHA3_HPP_

#include <cstdint>
#include <span>

namespace core::cryptography {

    inline constexpr std::size_t kStateBytes = 200;
    inline constexpr std::size_t kNumRounds = 24;
    inline constexpr std::size_t kWidth = 1600;

    using State = std::array<uint8_t, kStateBytes>;


    // Low-level Keccak sponge
    void KeccakF1600_statePermute(State &state) noexcept;

    void Keccak(uint32_t rate, uint32_t capacity,
                std::span<const uint8_t> input,
                uint8_t delimitedSuffix,
                std::span<uint8_t> output) noexcept;
    
    // SHA-3 hash functions
    void SHA3_224(std::span<const uint8_t> input, std::span<uint8_t, 28> output) noexcept;
    void SHA3_256(std::span<const uint8_t> input, std::span<uint8_t, 32> output) noexcept;
    void SHA3_384(std::span<const uint8_t> input, std::span<uint8_t, 48> output) noexcept;
    void SHA3_512(std::span<const uint8_t> input, std::span<uint8_t, 64> output) noexcept;

    // SHA-3 convenience overloads
    [[nodiscard]] std::array<uint8_t, 28> SHA3_224(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] std::array<uint8_t, 32> SHA3_256(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] std::array<uint8_t, 48> SHA3_384(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] std::array<uint8_t, 64> SHA3_512(std::span<const uint8_t> input) noexcept;

    // SHAKE extendable-output functions (XOFs)
    void SHAKE128(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept;
    void SHAKE256(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept;


} // namespace core::cryptography

#endif // _PQVPN_CORE_CRYPTOGRAPHY_SHA3_HPP_