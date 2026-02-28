#include "keccak.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <ranges>

namespace core::cryptography {

    // Internal helpers
    namespace keccak_internals {

        // Reference 
        // https://keccak.team/keccak_specs_summary.html

        

    } // namespace keccak_internals

    void KeccakF1600_statePermute(State &state) noexcept {

    }

    void Keccak(uint32_t rate, uint32_t capacity,
                std::span<const uint8_t> input,
                uint8_t delimitedSuffix,
                std::span<uint8_t> output) noexcept {

        //
    }
    
    // SHA-3 hash functions
    void SHA3_224(std::span<const uint8_t> input, std::span<uint8_t, 28> output) noexcept {
        Keccak(1152, 448, input, 0x06, output);
    }
    
    void SHA3_256(std::span<const uint8_t> input, std::span<uint8_t, 32> output) noexcept {
        Keccak(1088, 512, input, 0x06, output);
    }

    void SHA3_384(std::span<const uint8_t> input, std::span<uint8_t, 48> output) noexcept {
        Keccak(832, 768, input, 0x06, output);
    }

    void SHA3_512(std::span<const uint8_t> input, std::span<uint8_t, 64> output) noexcept {
        Keccak(576, 1024, input, 0x06, output);
    }

    // SHA-3 convenience overloads
    [[nodiscard]] std::array<uint8_t, 28> SHA3_224(std::span<const uint8_t> input) noexcept {
        std::array<uint8_t, 28> out{};
        SHA3_224(input, out);
        return out;
    }

    [[nodiscard]] std::array<uint8_t, 32> SHA3_256(std::span<const uint8_t> input) noexcept {
        std::array<uint8_t, 32> out{};
        SHA3_256(input, out);
        return out;
    }
    
    [[nodiscard]] std::array<uint8_t, 48> SHA3_384(std::span<const uint8_t> input) noexcept {
        std::array<uint8_t, 48> out{};
        SHA3_384(input, out);
        return out;
    }

    [[nodiscard]] std::array<uint8_t, 64> SHA3_512(std::span<const uint8_t> input) noexcept {
        std::array<uint8_t, 64> out{};
        SHA3_512(input, out);
        return out;
    }

    // SHAKE extendable-output functions (XOFs)
    void SHAKE128(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
        Keccak(1344, 256, input, 0x1F, output);
    }
    
    void SHAKE256(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
        Keccak(1088, 512, input, 0x1F, output);
    }

} // namespace core::cryptography