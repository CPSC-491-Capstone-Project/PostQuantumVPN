// The cpp implementation is in os/specific_os
// This is because the udp socket implementation is os specific
// This header serves as an os agnostic udp socket interface

#ifndef _PQVPN_CORE_NETWORK_UDP_SOCKET_HPP_
#define _PQVPN_CORE_NETWORK_UDP_SOCKET_HPP_

#include "network_constants.hpp"

#include <cstdint>
#include <string>
#include <span>
#include <cstddef>
#include <optional>


namespace core::network {
    using Data = std::span<std::uint8_t>;
    using BytesTransferred = std::ptrdiff_t;

    struct Endpoint {
        std::string ip{};
        std::uint16_t port{};
    };

    struct ReceiveResult {
        std::size_t bytes_read{0};
        Endpoint sender{};
    };

    class UDPSocket {
    public:
        UDPSocket() = default;
        ~UDPSocket();

        UDPSocket(const UDPSocket&) = delete;
        UDPSocket& operator=(const UDPSocket&) = delete;
        UDPSocket(UDPSocket&& other) noexcept;
        UDPSocket& operator=(UDPSocket&& other) noexcept;

        bool Open();
        bool Bind(const std::string& ip, std::uint16_t port);
        void Close();

        bool SetNonBlocking(bool do_not_block = true);

        BytesTransferred SendTo(const Endpoint& destination, Data data);
        std::optional<ReceiveResult> ReceiveFrom(Data data);

        [[nodiscard]] Handle GetHandle() const { return handle_; }
        [[nodiscard]] bool IsOpen() const { return handle_ != kInvalidHandle; }
        [[nodiscard]] std::optional<Endpoint> GetLocalEndpoint() const;

    private:
        Handle handle_{kInvalidHandle};
    };

}

#endif // _PQVPN_CORE_NETWORK_UDP_SOCKET_HPP_