#ifndef _PQVPN_SERVER_SERVER_HPP_
#define _PQVPN_SERVER_SERVER_HPP_

#include "tun_device.hpp"
#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "ipv4.hpp"
#include "handshake_processor.hpp"
#include "handshake_constants.hpp"
#include "peer.hpp"
#include "index_table.hpp"
#include "session_manager.hpp"
#include "x25519.hpp"

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

namespace server {

    using core::network::TunDevice;
    using core::network::EventMask;
    using core::network::PollEvent;
    using core::network::Endpoint;
    using core::network::EventPoller;
    using core::network::UDPSocket;
    using core::network::IPv4;
    using core::network::Data;
    using core::network::ConstData;
    using core::network::Port;

    using core::handshake::MessageType;
    using core::handshake::Peer;
    using core::handshake::IndexTable;
    using core::session::SessionManager;

    class Server {
    public:
        Server() = default;
        ~Server();

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&&) = delete;
        Server& operator=(Server&&) = delete;

        // -----------------------------------------------------------------
        // Builder: chain configuration calls before Init()
        // -----------------------------------------------------------------
        Server& SetBindAddress(IPv4 ip);
        Server& SetPort(Port port);
        Server& SetPollTimeoutMs(int timeout_ms);
        Server& SetTunInterface(std::string_view ifname);

        // Client's static X25519 public key — must be set before Init().
        // ConsumeMessageInitiation verifies the decrypted initiator key
        // against this value; no key means all handshakes are rejected.
        Server& SetPeerStaticX25519(core::cryptography::x25519::PublicKey pub);

        // -----------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------

        bool Init();
        bool Run();
        void Stop();
        void Shutdown();

        // -----------------------------------------------------------------
        // Queries
        // -----------------------------------------------------------------
        [[nodiscard]] bool IsRunning() const { return running_.load(std::memory_order_relaxed); }
        [[nodiscard]] bool IsInitialized() const { return initialized_; }

        [[nodiscard]] const UDPSocket&   GetSocket() const { return socket_; }
        [[nodiscard]] const EventPoller& GetPoller() const { return poller_; }

    private:

        // -----------------------------------------------------------------
        // Configuration
        // -----------------------------------------------------------------
        IPv4        bind_ip_{};
        Port        port_{};
        int         poll_timeout_ms_{250};
        std::string tun_ifname_{};

        // -----------------------------------------------------------------
        // Runtime state
        // -----------------------------------------------------------------
        UDPSocket   socket_{};
        TunDevice   tun_{};
        EventPoller poller_{};

        // Buffers live here so the event loop doesn't allocate on every packet
        std::array<std::uint8_t, 4096> recv_buf_{};
        std::array<std::uint8_t, 4096> tun_buf_{};

        std::atomic<bool> running_{false};
        bool initialized_{false};
        bool stopped_{false};
        std::thread worker_thread_{};

        // -----------------------------------------------------------------
        // Handshake / session state
        // -----------------------------------------------------------------
        Peer            peer_{};
        IndexTable      index_table_{};
        SessionManager  session_manager_{};

        // Set when a session becomes active (handshake complete).
        Endpoint        peer_endpoint_{};
        std::uint32_t   active_local_index_{0};

        // -----------------------------------------------------------------
        // Event loop
        // -----------------------------------------------------------------
        void EventLoop();

        // -----------------------------------------------------------------
        // Message handlers
        // -----------------------------------------------------------------
        void HandleInitiation(ConstData data, const Endpoint& sender);
        void HandleResponse(ConstData data, const Endpoint& sender);
        void HandleCookie(ConstData data, const Endpoint& sender);
        void HandleTransport(ConstData data, const Endpoint& sender);
        void HandleTunReadable();

        // Called once per poll iteration for periodic housekeeping
        void TimerTick();

        // -----------------------------------------------------------------
        // Internal helpers
        // -----------------------------------------------------------------

        // Generates server static keys, precomputes static-static DH,
        // and logs the server's public keys so the client can be configured.
        bool InitPeer();

        static std::string FormatEndpoint(const Endpoint& ep);
        void CleanupResources();
    };

} // namespace server

#endif // _PQVPN_SERVER_SERVER_HPP_
