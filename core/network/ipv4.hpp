#ifndef _PQVPN_CORE_NETWORK_IPv4_HPP_
#define _PQVPN_CORE_NETWORK_IPv4_HPP_

#include <cstdint>
#include <string>
#include <array>
#include <bit>

namespace core::network {
    class IPv4 {
    public:

        // Constructors
        constexpr IPv4() noexcept = default;

        constexpr IPv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept
            : addr_{Pack(a, b, c, d)} {}

        explicit constexpr IPv4(std::uint32_t host_order) noexcept
            : addr_{host_order} {}

        explicit IPv4(const std::string& dotted);

        // Getters
        [[nodiscard]] std::string ToString() const;
        [[nodiscard]] constexpr std::uint32_t ToHostOrder() const noexcept { return addr_; }
        [[nodiscard]] constexpr std::uint32_t ToNetworkOrder() const noexcept { return HostToNetwork(addr_); }
        [[nodiscard]] constexpr std::array<std::uint8_t, 4> Octets() const noexcept { return Unpack(addr_); }
        [[nodiscard]] constexpr bool IsValid() const noexcept { return valid_; }

        // Comparison 
        constexpr bool operator==(const IPv4& other) const noexcept = default;
        constexpr auto operator<=>(const IPv4& other) const noexcept = default;

        // Common Constants
        static consteval IPv4 Any() { return {std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{0}}; } // 0.0.0.0
        static consteval IPv4 Loopback() { return {std::uint8_t{127}, std::uint8_t{0}, std::uint8_t{0}, std::uint8_t{1}}; } // 127.0.0.1
        static consteval IPv4 Broadcast() { return {std::uint8_t{255}, std::uint8_t{255}, std::uint8_t{255}, std::uint8_t{255}}; } // 255.255.255.255



    private:
        std::uint32_t addr_{0};
        bool valid_{true};

        /// Pack four octets into a host-order uint32_t.
        /// Octets are always in "human" order (a = most significant).
        /// The arithmetic value always places octet a in bits 31..24
        /// regardless of the platform's native byte order.
        static constexpr std::uint32_t Pack(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
            return (static_cast<std::uint32_t>(a) << 24) |
                   (static_cast<std::uint32_t>(b) << 16) |
                   (static_cast<std::uint32_t>(c) <<  8) |
                   (static_cast<std::uint32_t>(d));
        }

        /// Unpack a host-order uint32_t back into four octets.
        static constexpr std::array<std::uint8_t, 4> Unpack(std::uint32_t v) noexcept {
            return {
                static_cast<std::uint8_t>((v >> 24) & 0xFF),
                static_cast<std::uint8_t>((v >> 16) & 0xFF),
                static_cast<std::uint8_t>((v >>  8) & 0xFF),
                static_cast<std::uint8_t>((v      ) & 0xFF)
            };
        }

        /// Byte-swap a 32-bit value. std::byteswap is C++23 but not yet
        /// supported by Apple Clang, so we implement it manually.
        static constexpr std::uint32_t ByteSwap(std::uint32_t v) noexcept {
            return ((v & 0xFF000000u) >> 24) |
                   ((v & 0x00FF0000u) >>  8) |
                   ((v & 0x0000FF00u) <<  8) |
                   ((v & 0x000000FFu) << 24);
        }

        /// Convert a host-order value to network order (big-endian).
        static constexpr std::uint32_t HostToNetwork(std::uint32_t host) noexcept {
            if constexpr (std::endian::native == std::endian::big) {
                return host;
            } else {
                return ByteSwap(host);
            }
        }

        /// Convert a network-order (big-endian) value to host order.
        static constexpr std::uint32_t NetworkToHost(std::uint32_t net) noexcept {
            if constexpr (std::endian::native == std::endian::big) {
                return net;
            } else {
                return ByteSwap(net);
            }
        }

    };
} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_IPv4_HPP_