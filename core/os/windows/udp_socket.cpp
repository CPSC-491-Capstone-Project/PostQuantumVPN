#include "udp_socket.hpp"
#include "logger.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <utility>
#include <string>

using core::utils::Logger;

namespace {
    struct WinsockInit {
        WinsockInit() {
            WSADATA wsadata{};
            if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
                // Can't call Logger here (may not be initialized yet)
            }
        }
        ~WinsockInit() {
            WSACleanup();
        }
    };
    static WinsockInit g_winsock_init;
}

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

        SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            Logger::Error("UDPSocket: Failed to create socket: " + std::to_string(WSAGetLastError()));
            return false;
        }

        handle_ = static_cast<Handle>(s);
        return true;
    }

    bool UDPSocket::Bind(const IPv4 ip, Port port) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: Bind called on closed socket");
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);

        if (inet_pton(AF_INET, ip.ToString().c_str(), &addr.sin_addr) != 1) {
            Logger::Error("UDPSocket: Invalid bind address: " + ip.ToString());
            return false;
        }

        if (::bind(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            Logger::Error("UDPSocket: Failed to bind to " + ip.ToString() + ":" + std::to_string(port) +
                          " error: " + std::to_string(WSAGetLastError()));
            return false;
        }

        return true;
    }

    void UDPSocket::Close() {
        if (IsOpen()) {
            ::closesocket(static_cast<SOCKET>(handle_));
            handle_ = kInvalidHandle;
        }
    }

    bool UDPSocket::SetNonBlocking(bool do_not_block) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: SetNonBlocking called on closed socket");
            return false;
        }

        u_long mode = do_not_block ? 1u : 0u;
        if (::ioctlsocket(static_cast<SOCKET>(handle_), FIONBIO, &mode) == SOCKET_ERROR) {
            Logger::Warning("UDPSocket: Failed to set non-blocking mode: " + std::to_string(WSAGetLastError()));
            return false;
        }

        return true;
    }

    BytesTransferred UDPSocket::SendTo(const Endpoint& destination, Data data) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: SendTo called on closed socket");
            return -1;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(destination.port);

        if (inet_pton(AF_INET, destination.ip.ToString().c_str(), &addr.sin_addr) != 1) {
            Logger::Error("UDPSocket: Invalid destination address: " + destination.ip.ToString());
            return -1;
        }

        int sent = ::sendto(
            static_cast<SOCKET>(handle_),
            reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()),
            0,
            reinterpret_cast<const sockaddr*>(&addr),
            sizeof(addr)
        );

        if (sent == SOCKET_ERROR) {
            Logger::Error("UDPSocket: sendto failed: " + std::to_string(WSAGetLastError()));
            return -1;
        }

        return static_cast<BytesTransferred>(sent);
    }

    std::optional<ReceiveResult> UDPSocket::ReceiveFrom(Data data) {
        if (!IsOpen()) {
            Logger::Error("UDPSocket: ReceiveFrom called on closed socket");
            return std::nullopt;
        }

        sockaddr_in addr{};
        int addr_len = sizeof(addr);

        int received = ::recvfrom(
            static_cast<SOCKET>(handle_),
            reinterpret_cast<char*>(data.data()),
            static_cast<int>(data.size()),
            0,
            reinterpret_cast<sockaddr*>(&addr),
            &addr_len
        );

        if (received == SOCKET_ERROR) {
            Logger::Error("UDPSocket: recvfrom failed: " + std::to_string(WSAGetLastError()));
            return std::nullopt;
        }

        char ip_buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));

        return ReceiveResult{
            .bytes_read = static_cast<std::size_t>(received),
            .sender = Endpoint{
                .ip   = IPv4(std::string(ip_buf)),
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
        int len = sizeof(addr);

        if (::getsockname(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&addr), &len) == SOCKET_ERROR) {
            Logger::Error("UDPSocket: getsockname failed: " + std::to_string(WSAGetLastError()));
            return std::nullopt;
        }

        char ip_buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));

        return Endpoint{
            .ip   = IPv4(std::string(ip_buf)),
            .port = ntohs(addr.sin_port)
        };
    }

} // namespace core::network
