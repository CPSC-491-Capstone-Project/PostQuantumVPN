#include "udp_socket.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <utility>

using core::utils::Logger;

namespace core::network {

    UDPSocket::~UDPSocket() {
        Close();
    }

    UDPSocket::UDPSocket(UDPSocket&& other) noexcept
        : handle_{std::exchange(other.handle_, kInvalidHandle)} 
    {}

    UDPSocket& UDPSocket::operator=(UDPSocket&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = std::exchange(other.handle_, kInvalidHandle);
        }
        return *this;
    }

    bool UDPSocket::Open() {
        if (IsOpen()) {
            Logger::Warning("UDPSocket: Open called on already open socket");
            return false;
        }

        handle_ = static_cast<Handle>(::socket(AF_INET, SOCK_DGRAM, 0));
        if (handle_ < 0) {
            Logger::Error("UDPSocket: Failed to create socket");
            handle_ = kInvalidHandle;
            return false;
        }

        return true;
    }

    bool UDPSocket::Bind(const IPv4 ip, Port port) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: Bind called on closed socket");
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (::inet_pton(AF_INET, ip.ToString().c_str(), &addr.sin_addr) != 1) {
            Logger::Error("UDPSocket: Invalid bind address: " + ip.ToString());
            return false;
        }

        if (::bind(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            Logger::Error("UDPSocket: Failed to bind to " + ip.ToString() + ":" + std::to_string(port));
            return false;
        }
        
        return true;
    }

    void UDPSocket::Close() {
        if (IsOpen()) {
            ::close(handle_);
            handle_ = kInvalidHandle;
        }
    }

    bool UDPSocket::SetNonBlocking(bool do_not_block) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: SetNonBlocking called on closed socket");
            return false;
        }

        std::int32_t flags = ::fcntl(handle_, F_GETFL, 0);
        if (flags < 0) {
            Logger::Error("UDPSocket: Failed to get socket flags for socket: " + std::to_string(handle_));
            return false;
        }

        flags = do_not_block ? (flags | O_NONBLOCK) : (flags | ~O_NONBLOCK);

        if (::fcntl(handle_, F_SETFL, flags) < 0) {
            Logger::Warning("UDPSocket: Failed to set non-blocking mode on socket: " + std::to_string(handle_));
            return false;
        }

        return true;
    }

    BytesTransferred UDPSocket::SendTo(const Endpoint& destination, Data data) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket:: SendTo called on closed socket");
            return -1;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(destination.port);

        if (::inet_pton(AF_INET, destination.ip.ToString().c_str(), &addr.sin_addr) != 1) {
            Logger::Error("UDPSocket: Invalid destination address: " + destination.ip.ToString());
            return -1;
        }

        BytesTransferred sent = ::sendto(
            handle_,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<const sockaddr*>(&addr),
            sizeof(addr)
        );

        if (sent < 0) {
            Logger::Error("UDPSocket:: sendto failed for socket: " + std::to_string(handle_));
        }

        return sent;
    }

    std::optional<ReceiveResult> UDPSocket::ReceiveFrom(Data data) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: ReceiveFrom called on closed socket");
            return std::nullopt;
        }

        sockaddr_in addr{};
        socklen_t addr_len = sizeof(addr);

        BytesTransferred received = recvfrom(
            handle_,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<sockaddr*>(&addr),
            &addr_len
        );

        if (received < 0) {
            Logger::Error("UDPSocket: ReceiveFrom failled for socket: " + std::to_string(handle_));
            return std::nullopt;
        }

        char ip_buffer[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &addr.sin_addr, ip_buffer, sizeof(ip_buffer));

        return ReceiveResult{
            .bytes_read = static_cast<std::size_t>(received),
            .sender = Endpoint{
                .ip = IPv4(std::string(ip_buffer)),
                .port = ntohs(addr.sin_port)
            }
        };
    }

    std::optional<Endpoint> UDPSocket::GetLocalEndpoint() const {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: GetLocalEndpoint called on closed socket");
            return std::nullopt;
        }

        sockaddr_in addr{};
        socklen_t len = sizeof(addr);

        if (::getsockname(handle_, reinterpret_cast<sockaddr*>(&addr), &len) < 0) {
            Logger::Error("UDPSocket: getsockname failed for socket: " + std::to_string(handle_));
            return std::nullopt;
        }

        char ip_buf[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));

        return Endpoint{
            .ip = IPv4(std::string(ip_buf)),
            .port = ntohs(addr.sin_port)
        };
    }


} // namespace core::network

        
