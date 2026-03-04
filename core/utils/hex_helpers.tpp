#ifndef _PQVPN_CORE_UTILS_HEX_HELPERS_TPP_
#define _PQVPN_CORE_UTILS_HEX_HELPERS_TPP_


#include <concepts>
#include <cstdint>
#include <span>
#include <string>

namespace core::utils {

    static constexpr char kHex[] = "0123456789ABCDEF";

    template <typename T>
        requires (!std::unsigned_integral<T>) &&
        requires (const T& t) { std::span<const uint8_t>(t); }
    std::string ToHexString(const T& data) {
        if (data.empty()) return {};
        
        std::string result;
        result.reserve((data.size() * 2) + 2);
        result += "0x";
        for (const auto byte : data) {
            result += kHex[byte >> 4];
            result += kHex[byte & 0x0F];
        }
        return result;
    }

    template <std::unsigned_integral T>
    std::string ToHexString(T value) {
        static constexpr std::size_t digits = sizeof(T) * 2;
        std::string result;
        result.reserve(digits + 2);
        result += "0x";
        for (std::size_t i{digits}; i > 0; --i) {
            result += kHex[(value >> ((i - 1) * 4)) & 0x0F];
        }
        return result;
    }

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_HEX_HELPERS_TPP_