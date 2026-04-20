#ifndef _PQVPN_CORE_NETWORK_CONSTANTS_HPP_
#define _PQVPN_CORE_NETWORK_CONSTANTS_HPP_

#include <cstddef>
#include <cstdint>
#include <span>

namespace core::network {

    using Handle           = std::int32_t;
    using Port             = std::uint16_t;
    using Data             = std::span<std::uint8_t>;
    using ConstData        = std::span<const std::uint8_t>;
    using BytesTransferred = std::ptrdiff_t;

    inline constexpr Handle kInvalidHandle = -1;

    // KB
    constexpr std::size_t k_4KB = 4 * 1024;
    constexpr std::size_t k_8KB = 8 * 1024;
    constexpr std::size_t k_16KB = 16 * 1024;
    constexpr std::size_t k_32KB = 32 * 1024;
    constexpr std::size_t k_64KB = 64 * 1024;
    constexpr std::size_t k_128KB = 128 * 1024;
    constexpr std::size_t k_256KB = 256 * 1024;
    constexpr std::size_t k_512KB = 512 * 1024;

    // MB
    constexpr std::size_t k_4MB = 4 * 1024 * 1024;
    constexpr std::size_t k_8MB = 8 * 1024 * 1024;
    constexpr std::size_t k_16MB = 16 * 1024 * 1024;
    constexpr std::size_t k_32MB = 32 * 1024 * 1024;
    constexpr std::size_t k_64MB = 64 * 1024 * 1024;
    constexpr std::size_t k_128MB = 128 * 1024 * 1024;
    constexpr std::size_t k_256MB = 256 * 1024 * 1024;
    constexpr std::size_t k_512MB = 512 * 1024 * 1024;

} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_CONSTANTS_HPP_