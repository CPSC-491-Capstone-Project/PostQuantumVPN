#include "bit_utils.hpp"

namespace core::utils {

    std::vector<uint8_t> BitsToBytes(const std::vector<uint8_t>& bits) {
        const std::size_t len = bits.size() / 8;
        std::vector<uint8_t> bytes(len, 0);

        for (std::size_t i{0uz}; i < len; ++i) {
            const std::size_t base = i * 8;
            uint8_t byte{0u};
            for (std::size_t j{0uz}; j < 8; ++j) {
                byte |= static_cast<uint8_t>(bits[base + j] << j);
            }
            bytes[i] = byte;
        }

        return bytes;
    }

    std::vector<uint8_t> BytesToBits(const std::vector<uint8_t>& bytes) {
        const std::size_t len = bytes.size();
        std::vector<uint8_t> bits(8 * len, 0);

        std::vector<uint8_t> bytes_copy = bytes;
        for (std::size_t i{0uz}; i < len; ++i) {
            for (std::size_t j{0uz}; j < 8; ++j) {
                bits[8 * i + j] = bytes_copy[i] % 2;
                bytes_copy[i] /= 2;
            }
        }
        return bits;
    }

} // namespace core::utils