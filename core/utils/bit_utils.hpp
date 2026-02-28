#ifndef _PQVPN_CORE_UTILS_BIT_UTILS_HPP_
#define _PQVPN_CORE_UTILS_BIT_UTILS_HPP_

#include <cstdint>
#include <span>

namespace core::utils {

    // Converts a bit array (of length that is a multiple of eight) into an array of bytes.
    void BitsToBytes(std::span<const uint8_t> bits, std::span<uint8_t> bytes);

    // Performs the inverse of BitsToBytes, converting a byte array into a bit array.
    void BytesToBits(std::span<const uint8_t> bytes, std::span<uint8_t> bits);

    // Reads a 64-bit value from a byte buffer in little-endian order.
    inline uint64_t load64_le(const uint8_t *src);

    // Writes a 64-bit value to a byte buffer in little-endian order.
    inline void store64_le(uint8_t *dst, uint64_t val);


} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_BIT_UTILS_HPP_