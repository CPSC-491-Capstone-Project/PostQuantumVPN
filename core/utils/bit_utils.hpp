#ifndef _PQVPN_CORE_UTILS_BIT_UTILS_HPP_
#define _PQVPN_CORE_UTILS_BIT_UTILS_HPP_

#include <bit>
#include <cstdint>
#include <span>
#include <cstring>
#include <string>
#include <string_view>

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

    [[nodiscard]] constexpr inline int HexNibble(char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // Encode bytes as lowercase hex string (no prefix).
    [[nodiscard]] constexpr inline std::string ToHex(ConstByteSpan data) {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (auto b : data) {
            out += kHex[b >> 4];
            out += kHex[b & 0x0f];
        }
        return out;
    }

    // Decode lowercase or uppercase hex string into out.
    // Returns false if s.size() != out.size()*2 or any character is invalid.
    [[nodiscard]] constexpr inline bool FromHex(std::string_view s, ByteSpan out) noexcept {
        if (s.size() != out.size() * 2) return false;
        for (std::size_t i = 0; i < out.size(); ++i) {
            int hi = HexNibble(s[i * 2]);
            int lo = HexNibble(s[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return true;
    }

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_BIT_UTILS_HPP_