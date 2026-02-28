#include "bit_utils.hpp"

#include <cstring>

namespace core::utils {

    void BitsToBytes(std::span<const uint8_t> bits, std::span<uint8_t> bytes) {
        const auto num_bytes = bits.size() / 8uz;

        for (auto i{0uz}; i < num_bytes; ++i) {
            const auto base = i * 8uz;
            uint8_t byte{};
            for (auto j{0uz}; j < 8uz; ++j) {
                byte |= static_cast<uint8_t>((bits[base + j] & 1u) << j);
            }
            bytes[i] = byte;
        }
    }

    void BytesToBits(std::span<const uint8_t> bytes, std::span<uint8_t> bits) {
        for (auto i{0uz}; i < bytes.size(); ++i) {
            auto c = bytes[i];
            for (auto j{0uz}; j < 8uz; ++j) {
                bits[8uz * i + j] = c & 1u;
                c >>= 1;
            }
        }
    }

    inline uint64_t load64_le(const uint8_t *src) {
        uint64_t val;
        std::memcpy(&val, src, 8);
        if constexpr (std::endian::native != std::endian::little) {
            val = std::byteswap(val);
        }
        return val;
    }

    inline void store64_le(uint8_t *dst, uint64_t val) {   
        if constexpr (std::endian::native != std::endian::little) {
            val = std::byteswap(val);
        }
        std::memcpy(dst, &val, 8);
    }


} // namespace core::utils