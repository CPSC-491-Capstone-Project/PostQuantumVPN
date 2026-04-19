// The cpp implementation is in os/specific_os
// This is because the tun device implementation is os specific
// This header serves as an os agnostic tun device interface

#ifndef _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_
#define _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_

#include "network_constants.hpp"
#include "ipv4.hpp"

#include <bit>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace core::network {
    using ConstData = std::span<const std::uint8_t>;
    using Data = std::span<std::uint8_t>;
    using BytesTransferred = std::ptrdiff_t;

    class TunDevice {
    public:
        TunDevice() = default;
        ~TunDevice();

        TunDevice(const TunDevice&) = delete;
        TunDevice& operator=(const TunDevice&) = delete;
        TunDevice(TunDevice&& other) noexcept;
        TunDevice& operator=(TunDevice&& other) noexcept;

        bool Open(std::string_view ifname);
        void Close();

        bool SetNonBlocking(bool non_blocking = true);

        BytesTransferred Read(Data buf);
        BytesTransferred Write(ConstData buf);

        // Assigns ip/24 to this interface and brings it UP + RUNNING.
        // Must be called after a successful Open().
        bool BringUp(IPv4 ip);

        [[nodiscard]] Handle GetHandle() const { return handle_; }
        [[nodiscard]] bool IsOpen() const { return handle_ != kInvalidHandle; }

        // Returns true if a network interface with this name currently exists in the OS.
        static bool Exists(std::string_view name);

        // Returns true if the process has the privileges needed to open TUN devices.
        static bool HasRequiredPrivileges();

        // Builds a minimal valid IPv4/UDP datagram for injection via Write().
        // UDP checksum is disabled (legal in IPv4 — set to 0).
        static std::vector<uint8_t> BuildUdpPacket(
            IPv4 src_ip, IPv4 dst_ip,
            uint16_t src_port, uint16_t dst_port,
            ConstData payload);

        // Extract the destination IP from a raw IPv4 packet.
        // Returns nullopt if the packet is shorter than a minimal IP header.
        static std::optional<IPv4> ParseDstIP(ConstData packet);

        // Extract the source IP from a raw IPv4 packet.
        static std::optional<IPv4> ParseSrcIP(ConstData packet);

    private:
        Handle handle_{kInvalidHandle};
        std::string ifname_{};

        static constexpr uint16_t HostToNetwork16(uint16_t v) noexcept {
            if constexpr (std::endian::native == std::endian::big) return v;
            return static_cast<uint16_t>((v >> 8) | (v << 8));
        }

        static uint16_t IpChecksum(ConstData header) noexcept;
    };

} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_
