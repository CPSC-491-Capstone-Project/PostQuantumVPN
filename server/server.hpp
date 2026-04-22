#ifndef _PQVPN_SERVER_SERVER_HPP_
#define _PQVPN_SERVER_SERVER_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "ipv4.hpp"
#include "tun_device.hpp"
#include "handshake_constants.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <array>

namespace server {

    using core::network::EventMask;
    using core::network::PollEvent;
    using core::network::Endpoint;
    using core::network::EventPoller;
    using core::network::UDPSocket;
    using core::network::TunDevice;
    using core::network::IPv4;
    using core::network::Data;
    using core::network::ConstData;
    using core::network::Port;
    using core::network::BytesTransferred;
    using core::handshake::MessageType;

    class Server {
    public:
        Server() = default;
        ~Server();

        Server(const Server&)            = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&&)                 = delete;
        Server& operator=(Server&&)      = delete;

        // Builder — chain before Init()
        Server& SetBindAddress(IPv4 ip);
        Server& SetPort(Port port);
        Server& SetPollTimeoutMs(int timeout_ms);
        Server& SetTunInterface(std::string_view ifname, IPv4 tun_ip);

        // Lifecycle
        bool Init();
        bool Run();
        void Stop();
        void Shutdown();

        [[nodiscard]] bool IsRunning()     const { return running_.load(std::memory_order_relaxed); }
        [[nodiscard]] bool IsInitialized() const { return initialized_; }

    private:
        // ---------------------------------------------------------------
        // Configuration
        // ---------------------------------------------------------------
        IPv4        bind_ip_{};
        Port        port_{};
        int         poll_timeout_ms_{250};
        std::string tun_ifname_{"pqvpn0"};
        IPv4        tun_ip_{};
        bool        use_tun_{false};

        // ---------------------------------------------------------------
        // Network
        // ---------------------------------------------------------------
        UDPSocket   socket_{};
        EventPoller poller_{};
        TunDevice   tun_{};

        std::array<std::uint8_t, 4096> recv_buffer_{};
        std::array<std::uint8_t, 4096> tun_buffer_{};

        // ---------------------------------------------------------------
        // Routing: client VPN IP (host-order u32) → client UDP endpoint
        // ---------------------------------------------------------------
        std::unordered_map<std::uint32_t, Endpoint> ip_to_client_;
        std::mutex routing_mutex_{};

        // ---------------------------------------------------------------
        // Thread control
        // ---------------------------------------------------------------
        std::atomic<bool> running_{false};
        bool initialized_{false};
        bool stopped_{false};
        std::thread worker_thread_{};

        // ---------------------------------------------------------------
        // Event loop helpers
        // ---------------------------------------------------------------
        void EventLoop();
        void HandleTransport(ConstData data, const Endpoint& sender);
        void HandleTunRead();
        void TimerTick();

        static std::string FormatEndpoint(const Endpoint& ep);
        void CleanupResources();
    };

} // namespace server

#endif // _PQVPN_SERVER_SERVER_HPP_
