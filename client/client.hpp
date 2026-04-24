#ifndef _PQVPN_CLIENT_CLIENT_HPP_
#define _PQVPN_CLIENT_CLIENT_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "tun_device.hpp"
#include "handshake_constants.hpp"
#include "handshake_messages.hpp"
#include "handshake_processor.hpp"
#include "peer.hpp"
#include "index_table.hpp"
#include "session.hpp"
#include "session_manager.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace client {

using core::network::UDPSocket;
using core::network::EventPoller;
using core::network::TunDevice;
using core::network::EventMask;
using core::network::PollEvent;
using core::network::Endpoint;
using core::network::ConstData;
using core::network::Data;
using core::network::BytesTransferred;
using core::handshake::MessageType;
using core::handshake::Peer;
using core::handshake::IndexTable;
using core::session::Session;
using core::session::SessionManager;

class Client {
public:
    Client() = default;
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&)                 = delete;
    Client& operator=(Client&&)      = delete;

    // Configure TUN interface name and IP before calling Init().
    Client& SetTunInterface(std::string_view ifname, core::network::IPv4 ip);

    // Set client's own static key material.
    Client& SetStaticKeys(
        const core::cryptography::x25519::PrivateKey& x25519_priv,
        const core::cryptography::x25519::PublicKey&  x25519_pub,
        const std::array<std::uint8_t, 2400>&         mlkem_dk,
        const std::array<std::uint8_t, 1184>&          mlkem_ek);

    // Set server's public keys (pre-shared from configuration).
    Client& SetServerStaticKeys(
        const core::cryptography::x25519::PublicKey& server_x25519_pub,
        const std::array<std::uint8_t, 1184>&         server_mlkem_ek);

    // Opens socket (no bind), sets SO_MARK, sets non-blocking, stores server
    // endpoint, opens TUN, opens epoll, registers both fds for Readable.
    bool Init(const std::string& server_ip, std::uint16_t server_port);

    // Calls SendInitiation(), then polls until Stop() is called.
    void Run();

    // Sets running_ = false; a subsequent Run() call returns immediately.
    void Stop();

    // Closes TUN, poller, then socket.  Safe to call more than once.
    void Shutdown();

    [[nodiscard]] bool IsInitialized() const { return initialized_; }

private:
    // --- Network ---
    UDPSocket   socket_{};
    EventPoller poller_{};
    TunDevice   tun_{};

    // recv_buffer must hold the largest message (Initiation = 3620, Response = 2268)
    std::array<std::uint8_t, 4096> recv_buffer_{};
    std::array<std::uint8_t, 4096> tun_buffer_{};

    Endpoint    server_endpoint_{};

    // --- Client static keys ---
    core::cryptography::x25519::PrivateKey local_x25519_priv_{};
    core::cryptography::x25519::PublicKey  local_x25519_pub_{};
    std::array<std::uint8_t, 2400>          local_mlkem_dk_{};
    std::array<std::uint8_t, 1184>          local_mlkem_ek_{};

    // --- Server public keys (pre-shared) ---
    core::cryptography::x25519::PublicKey  server_x25519_pub_{};
    std::array<std::uint8_t, 1184>          server_mlkem_ek_{};

    // --- Handshake / session state ---
    Peer           peer_{};
    IndexTable     index_table_{};
    SessionManager sessions_{};

    std::uint32_t  active_session_index_{0};
    bool           has_session_{false};

    // --- Config ---
    std::string          tun_ifname_{"tun0"};
    core::network::IPv4  tun_ip_{};
    bool                 use_tun_{false};

    // --- State ---
    std::atomic<bool>     running_{false};
    bool initialized_{false};
    bool stopped_{false};

    // --- Stats ---
    std::atomic<std::uint64_t> bytes_sent_{0};
    std::atomic<std::uint64_t> bytes_recv_{0};
    std::chrono::steady_clock::time_point last_stats_time_{};

    // --- Event handlers ---
    void HandleTunRead();
    void SendInitiation();
    void HandleInitiation(ConstData data, const Endpoint& sender);
    void HandleResponse(ConstData data, const Endpoint& sender);
    void HandleCookie(ConstData data, const Endpoint& sender);
    void HandleTransport(ConstData data, const Endpoint& sender);
    void SendTransport(Session& session, ConstData plaintext);
    void TimerTick();

    static std::string FormatEndpoint(const Endpoint& ep);
};

} // namespace client

#endif // _PQVPN_CLIENT_CLIENT_HPP_
