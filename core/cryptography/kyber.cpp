#include "kyber.hpp"
#include "bit_utils.hpp"

#include <array>

namespace core::cryptography::kyber {

    void ByteEncode(uint8_t d, std::span<const uint16_t, N> F, std::span<uint8_t> bytes) {

        std::array<uint8_t, N * 12> bits{};

        for (auto i{0uz}; i < N; ++i) {
            uint16_t a = F[i];
            for (auto j{0u}; j < d; ++j) {
                bits[i * d + j] = a % 2;
                a = static_cast<uint16_t>((a - bits[i * d + j]) / 2); // a - bits[i * d + j] is always event
            }
        }

        core::utils::BitsToBytes({bits.data(), static_cast<size_t>(N * d)}, bytes);
    }

    void ByteDecode(uint8_t d, std::span<const uint8_t> bytes, std::span<uint16_t, N> F) {

        const uint16_t m = (d < 12)? static_cast<uint16_t>(1u << d) : Q;

        std::array<uint8_t, N * 12> bits{};
        core::utils::BytesToBits(bytes, {bits.data(), static_cast<std::size_t>(N * d)});

        for (auto i{0uz}; i < N; ++i) {
            uint32_t sum{};
            for (uint8_t j{0u}; j < d; ++j) {
                sum += static_cast<uint32_t>(bits[i * d + j]) << j;
            }
            F[i] = static_cast<uint16_t>(sum % m);
        }

    }


}