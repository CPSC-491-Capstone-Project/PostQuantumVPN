// The cpp implementation is in os/specific_os
// This is because the tun device implementation is os specific
// This header serves as an os agnostic tun device interface

#ifndef _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_
#define _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_

#include "network_constants.hpp"

#include <cstdint>
#include <span>
#include <string_view>

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

        [[nodiscard]] Handle GetHandle() const { return handle_; }
        [[nodiscard]] bool IsOpen() const { return handle_ != kInvalidHandle; }

    private:
        Handle handle_{kInvalidHandle};
    };

} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_TUN_DEVICE_HPP_
