#ifndef _PQVPN_SERVER_SERVER_HPP_
#define _PQVPN_SERVER_SERVER_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "ipv4.hpp"
#include "tun_device.hpp"
#include "handshake_constants.hpp"
#include "handshake_processor.hpp"
#include "handshake_messages.hpp"
#include "peer.hpp"
#include "index_table.hpp"
#include "session.hpp"
#include "session_manager.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
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
    using core::handshake::Peer;
    using core::handshake::IndexTable;
    using core::session::Session;
    using core::session::SessionManager;

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
        Server& SetStaticKeys(
            const core::cryptography::x25519::PrivateKey&  x25519_priv,
            const core::cryptography::x25519::PublicKey&   x25519_pub,
            const std::array<std::uint8_t, 2400>&           mlkem_dk,
            const std::array<std::uint8_t, 1184>&           mlkem_ek);

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

        // Server static keys
        core::cryptography::x25519::PrivateKey local_x25519_priv_{};
        core::cryptography::x25519::PublicKey  local_x25519_pub_{};
        std::array<std::uint8_t, 2400>          local_mlkem_dk_{};
        std::array<std::uint8_t, 1184>          local_mlkem_ek_{};

        // ---------------------------------------------------------------
        // Network
        // ---------------------------------------------------------------
        UDPSocket   socket_{};
        EventPoller poller_{};
        TunDevice   tun_{};

        // recv_buffer must hold the largest message (Initiation = 3620 bytes)
        std::array<std::uint8_t, 4096> recv_buffer_{};
        std::array<std::uint8_t, 4096> tun_buffer_{};

        // ---------------------------------------------------------------
        // Handshake / session state
        // ---------------------------------------------------------------
        IndexTable     index_table_{};
        SessionManager sessions_{};

        // Per-client Peer objects, keyed by our local handshake index.
        // Owned here so the raw pointers in IndexTable remain valid.
        std::unordered_map<std::uint32_t, std::unique_ptr<Peer>> peers_;
        std::mutex peers_mutex_{};

        // Client VPN IP (host-order u32) → session sender_index for TUN→client routing
        std::unordered_map<std::uint32_t, std::uint32_t> ip_to_session_;
        std::mutex routing_mutex_{};

        // ---------------------------------------------------------------
        // Thread control
        // ---------------------------------------------------------------
        std::atomic<bool> running_{false};
        bool initialized_{false};
        bool stopped_{false};
        std::thread worker_thread_{};

        // ---------------------------------------------------------------
        // Event loop
        // ---------------------------------------------------------------
        void EventLoop();

        // ---------------------------------------------------------------
        // Message handlers
        // ---------------------------------------------------------------
        void HandleInitiation(ConstData data, const Endpoint& sender);
        void HandleResponse(ConstData data, const Endpoint& sender);
        void HandleCookie(ConstData data, const Endpoint& sender);
        void HandleTransport(ConstData data, const Endpoint& sender);

        void HandleTunRead();
        void SendTransport(Session& session, ConstData plaintext);

        void TimerTick();

        static std::string FormatEndpoint(const Endpoint& ep);
        void CleanupResources();
    };

} // namespace server

#endif // _PQVPN_SERVER_SERVER_HPP_
