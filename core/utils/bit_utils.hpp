#ifndef _PQVPN_CORE_UTILS_BIT_UTILS_HPP_
#define _PQVPN_CORE_UTILS_BIT_UTILS_HPP_

#include <bit>
#include <cstdint>
#include <span>
#include <cstring>
#include <string>
#include <bit>

namespace core::utils {

    using ByteSpan = std::span<std::uint8_t>;
    using ConstByteSpan = std::span<const std::uint8_t>;

    // Non-cryptographic, fast hashing function
    [[nodiscard]] static constexpr std::uint64_t Fnv1a(ConstByteSpan data) {
        auto hash = std::uint64_t{14695981039346656037ULL};
        for (auto i{0uz}; i < data.size(); ++i) {
            hash ^= static_cast<std::uint64_t>(data[i]);
            hash *= std::uint64_t{1099511628211ULL};
        }
        return hash;
    }

    // Converts a bit array (of length that is a multiple of eight) into an array of bytes.
    void BitsToBytes(ConstByteSpan bits, ByteSpan bytes);

    // Performs the inverse of BitsToBytes, converting a byte array into a bit array.
    void BytesToBits(ConstByteSpan bytes, ByteSpan bits);

    // Reads a 64-bit value from a byte buffer in little-endian order.
    inline uint64_t load64_le(const uint8_t *src) {
        uint64_t val;
        std::memcpy(&val, src, 8);
        if constexpr (std::endian::native != std::endian::little) {
            val = std::byteswap(val);
        }
        return val;
    }

    // Writes a 64-bit value to a byte buffer in little-endian order.
    inline void store64_le(uint8_t *dst, uint64_t val) {   
        if constexpr (std::endian::native != std::endian::little) {
            val = std::byteswap(val);
        }
        std::memcpy(dst, &val, 8);
    }


} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_BIT_UTILS_HPP_