#include "server.hpp"
#include "handshake_constants.hpp"
#include "handshake_processor.hpp"
#include "logger.hpp"
#include "ml_kem.hpp"

#include <chrono>
#include <cstring>
#include <openssl/evp.h>

namespace server {

using core::utils::Logger;
using core::handshake::InitHandshakeConstants;
using core::handshake::ConsumeMessageInitiation;
using core::handshake::CreateMessageResponse;
using core::handshake::DeriveSessionKeys;
using core::handshake::kRekeyAfterTime;
using core::handshake::kRejectAfterTime;
using core::handshake::kMlKemDecapsulationKeyBytes;
using core::session::SessionSecrets;

// ---------------------------------------------------------------------------
// LE helpers — endian-neutral read/write without OS headers
// ---------------------------------------------------------------------------
static inline std::uint32_t ReadLE32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0])
         | static_cast<std::uint32_t>(p[1]) << 8
         | static_cast<std::uint32_t>(p[2]) << 16
         | static_cast<std::uint32_t>(p[3]) << 24;
}
static inline std::uint16_t ReadLE16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0])
         | static_cast<std::uint16_t>(p[1]) << 8;
}
static inline void WriteLE32(std::uint8_t* p, std::uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline void WriteLE16(std::uint8_t* p, std::uint16_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
}

// Minimal hex formatter for logging public keys
static std::string ToHex(const std::uint8_t* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        s += kHex[data[i] >> 4];
        s += kHex[data[i] & 0xf];
    }
    return s;
}

// =========================================================================
// Lifecycle
// =========================================================================

Server::~Server() { Shutdown(); }

// =========================================================================
// Builder setters
// =========================================================================

Server& Server::SetBindAddress(IPv4 ip)           { bind_ip_ = ip;         return *this; }
Server& Server::SetPort(Port port)                 { port_ = port;          return *this; }
Server& Server::SetPollTimeoutMs(int ms)           { poll_timeout_ms_ = ms; return *this; }
Server& Server::SetTunInterface(std::string_view n){ tun_ifname_ = n;       return *this; }

Server& Server::SetPeerStaticX25519(core::cryptography::x25519::PublicKey pub) {
    peer_.remote_static_x25519 = pub;
    return *this;
}

// =========================================================================
// Init
// =========================================================================

bool Server::InitPeer() {
    // Generate server static X25519 keypair
    auto x25519_kp = core::cryptography::x25519::GenerateKeyPair();
    if (!x25519_kp) {
        Logger::Error("Server: Failed to generate X25519 static keypair");
        return false;
    }
    peer_.local_static_x25519_private = x25519_kp->private_key;
    peer_.local_static_x25519_public  = x25519_kp->public_key;

    // Generate server static ML-KEM-768 keypair
    auto mlkem_kp = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!mlkem_kp) {
        Logger::Error("Server: Failed to generate ML-KEM static keypair");
        return false;
    }
    // Extract raw decapsulation key (private) — 2400 bytes
    std::size_t dk_len = kMlKemDecapsulationKeyBytes;
    if (EVP_PKEY_get_raw_private_key(mlkem_kp->pkey.get(),
                                     peer_.local_static_mlkem_dk.data(),
                                     &dk_len) != 1
        || dk_len != kMlKemDecapsulationKeyBytes) {
        Logger::Error("Server: Failed to extract ML-KEM decapsulation key");
        return false;
    }
    // Encapsulation key (public) — 1184 bytes
    if (mlkem_kp->public_key.size() != core::handshake::kMlKemEncapsulationKeyBytes) {
        Logger::Error("Server: ML-KEM public key has unexpected size");
        return false;
    }
    std::copy(mlkem_kp->public_key.begin(), mlkem_kp->public_key.end(),
              peer_.local_static_mlkem_ek.begin());

    // Log public keys so the client can be configured
    Logger::Info("Server: === Static Public Keys (configure these on the client) ===");
    Logger::Info("Server: X25519  pub = "
                 + ToHex(peer_.local_static_x25519_public.data(),
                         peer_.local_static_x25519_public.size()));
    Logger::Info("Server: ML-KEM  ek  = "
                 + ToHex(peer_.local_static_mlkem_ek.data(),
                         peer_.local_static_mlkem_ek.size()));
    Logger::Info("Server: ==========================================================");

    // Warn if the client's public key hasn't been configured
    static constexpr core::cryptography::x25519::PublicKey kZero{};
    if (peer_.remote_static_x25519 == kZero) {
        Logger::Warning("Server: Peer X25519 public key not configured — "
                        "all handshakes will be rejected. "
                        "Call SetPeerStaticX25519() before Init().");
        // Don't fail — server still runs, no handshake will complete
        return true;
    }

    // Precompute static-static X25519 shared secret — used every handshake
    auto ss = core::cryptography::x25519::DeriveSharedSecret(
        peer_.local_static_x25519_private, peer_.remote_static_x25519);
    if (!ss) {
        Logger::Error("Server: Failed to precompute static-static DH");
        return false;
    }
    peer_.precomputed_static_static = *ss;

    return true;
}

bool Server::Init() {
    if (initialized_) {
        Logger::Warning("Server: Init called on already-initialized server");
        return false;
    }
    if (!bind_ip_.IsValid()) {
        Logger::Error("Server: Bind address is invalid");
        return false;
    }

    // Handshake protocol constants — idempotent, safe to call multiple times
    InitHandshakeConstants();

    // Generate static key material and configure peer
    if (!InitPeer()) return false;

    // UDP socket
    if (!socket_.Open()) {
        Logger::Error("Server: Failed to open UDP socket");
        return false;
    }
    if (!socket_.Bind(bind_ip_, port_)) {
        Logger::Error("Server: Failed to bind to "
                      + bind_ip_.ToString() + ":" + std::to_string(port_));
        CleanupResources();
        return false;
    }
    if (!socket_.SetNonBlocking()) {
        Logger::Error("Server: Failed to set socket non-blocking");
        CleanupResources();
        return false;
    }

    // Event poller
    if (!poller_.Open()) {
        Logger::Error("Server: Failed to create event poller");
        CleanupResources();
        return false;
    }
    if (!poller_.Add(socket_.GetHandle(), EventMask::Readable)) {
        Logger::Error("Server: Failed to register socket with poller");
        CleanupResources();
        return false;
    }

    // TUN device (optional — server works without it, just can't forward)
    if (!tun_ifname_.empty()) {
        if (!tun_.Open(tun_ifname_)) {
            Logger::Error("Server: Failed to open TUN device '" + tun_ifname_ + "'");
            CleanupResources();
            return false;
        }
        if (!tun_.SetNonBlocking()) {
            Logger::Error("Server: Failed to set TUN non-blocking");
            CleanupResources();
            return false;
        }
        if (!poller_.Add(tun_.GetHandle(), EventMask::Readable)) {
            Logger::Error("Server: Failed to register TUN with poller");
            CleanupResources();
            return false;
        }
        Logger::Info("Server: TUN device '" + tun_ifname_ + "' opened");
    }

    initialized_ = true;
    Logger::Info("Server: Initialized on "
                 + bind_ip_.ToString() + ":" + std::to_string(port_));
    return true;
}

// =========================================================================
// Run / Stop / Shutdown
// =========================================================================

bool Server::Run() {
    if (!initialized_) {
        Logger::Error("Server: Run called before successful Init");
        return false;
    }
    if (stopped_) {
        Logger::Warning("Server: Run called after Stop");
        return false;
    }
    if (running_.load(std::memory_order_relaxed)) {
        Logger::Warning("Server: Run called while already running");
        return false;
    }
    running_.store(true, std::memory_order_relaxed);
    worker_thread_ = std::thread(&Server::EventLoop, this);
    Logger::Info("Server: Event loop started");
    return true;
}

void Server::Stop() {
    stopped_ = true;
    running_.store(false, std::memory_order_relaxed);
    Logger::Info("Server: Stop requested");
}

void Server::Shutdown() {
    Stop();
    if (worker_thread_.joinable()) worker_thread_.join();
    CleanupResources();
    initialized_ = false;
    stopped_      = false;
    Logger::Info("Server: Shutdown complete");
}

// =========================================================================
// Event loop
// =========================================================================

void Server::EventLoop() {
    Logger::Info("Server: Entering event loop");

    std::array<PollEvent, 4> events{};

    while (running_.load(std::memory_order_relaxed)) {
        int count = poller_.Poll(events, poll_timeout_ms_);

        if (count < 0) {
            Logger::Error("Server: Poll error — stopping loop");
            break;
        }

        for (int i = 0; i < count; ++i) {
            const auto& ev = events[static_cast<std::size_t>(i)];

            if (ev.IsError() || ev.IsHangup()) {
                Logger::Error("Server: Error/Hangup on handle " + std::to_string(ev.handle));
                running_.store(false, std::memory_order_relaxed);
                break;
            }

            if (!ev.IsReadable()) continue;

            // --- TUN fd readable: response from the internet ---
            if (tun_.IsOpen() && ev.handle == tun_.GetHandle()) {
                HandleTunReadable();
                continue;
            }

            // --- UDP socket readable: packet from peer ---
            if (ev.handle != socket_.GetHandle()) continue;

            auto result = socket_.ReceiveFrom(recv_buf_);
            if (!result || result->bytes_read == 0) continue;

            ConstData payload{recv_buf_.data(), result->bytes_read};
            const auto type = static_cast<MessageType>(recv_buf_[0]);

            switch (type) {
                case MessageType::Initiation:
                    HandleInitiation(payload, result->sender);
                    break;
                case MessageType::Response:
                    HandleResponse(payload, result->sender);
                    break;
                case MessageType::Cookie:
                    HandleCookie(payload, result->sender);
                    break;
                case MessageType::Transport:
                    HandleTransport(payload, result->sender);
                    break;
                default:
                    Logger::Warning("Server: Unknown message type "
                                    + std::to_string(recv_buf_[0])
                                    + " from " + FormatEndpoint(result->sender));
            }
        }

        TimerTick();
    }

    Logger::Info("Server: Exiting event loop");
}

// =========================================================================
// HandleInitiation
// =========================================================================

void Server::HandleInitiation(ConstData data, const Endpoint& sender) {
    Logger::Debug("Server: HandleInitiation — "
                  + std::to_string(data.size()) + " bytes from "
                  + FormatEndpoint(sender));

    if (!ConsumeMessageInitiation(data, peer_)) {
        Logger::Warning("Server: ConsumeMessageInitiation failed from "
                        + FormatEndpoint(sender));
        return;
    }

    auto response = CreateMessageResponse(peer_, index_table_);
    if (!response) {
        Logger::Error("Server: CreateMessageResponse failed");
        return;
    }

    ConstData resp_data{response->data(), response->size()};
    if (socket_.SendTo(sender, {const_cast<std::uint8_t*>(resp_data.data()),
                                resp_data.size()}) < 0) {
        Logger::Error("Server: Failed to send response to " + FormatEndpoint(sender));
        return;
    }

    if (!DeriveSessionKeys(peer_, index_table_, /*is_initiator=*/false)) {
        Logger::Error("Server: DeriveSessionKeys failed");
        return;
    }

    // Responder puts the keypair in Next slot; grab it before activating session
    auto* kp = peer_.keypairs.Next();
    if (!kp) {
        Logger::Error("Server: No keypair in Next slot after DeriveSessionKeys");
        return;
    }

    // Bridge handshake keypair → SessionManager
    SessionSecrets secrets;
    secrets.send_key       = kp->send_key;
    secrets.recv_key       = kp->receive_key;
    secrets.sender_index   = kp->local_index;
    secrets.receiver_index = kp->remote_index;
    secrets.is_initiator   = false;

    auto* session = session_manager_.ActivateSession(secrets, sender);
    if (!session) {
        Logger::Error("Server: SessionManager::ActivateSession failed");
        return;
    }

    // Remove previous session if one existed
    if (active_local_index_ != 0 && active_local_index_ != secrets.sender_index) {
        session_manager_.Remove(active_local_index_);
    }

    active_local_index_ = secrets.sender_index;
    peer_endpoint_       = sender;

    // Promote keypair from Next → Current (first transport will also do this,
    // but doing it here keeps keypairs.Current() valid immediately)
    peer_.keypairs.PromoteNext();

    Logger::Info("Server: Handshake complete with " + FormatEndpoint(sender)
                 + " [local_idx=" + std::to_string(secrets.sender_index)
                 + " remote_idx=" + std::to_string(secrets.receiver_index) + "]");
}

// =========================================================================
// HandleResponse  (server never initiates, so this is unexpected)
// =========================================================================

void Server::HandleResponse(ConstData data, const Endpoint& sender) {
    Logger::Debug("Server: HandleResponse (unexpected) — "
                  + std::to_string(data.size()) + " bytes from "
                  + FormatEndpoint(sender));
}

// =========================================================================
// HandleCookie
// =========================================================================

void Server::HandleCookie(ConstData data, const Endpoint& sender) {
    Logger::Debug("Server: HandleCookie — "
                  + std::to_string(data.size()) + " bytes from "
                  + FormatEndpoint(sender));
}

// =========================================================================
// HandleTransport
// =========================================================================
//
// Plaintext transport frame (no encryption):
//   [0]     type         = 0x04
//   [1..4]  receiver_index (uint32 LE) — our local index
//   [5..6]  length       (uint16 LE)
//   [7..]   raw IPv4 packet

void Server::HandleTransport(ConstData data, const Endpoint& sender) {
    static constexpr std::size_t kHeaderSize = 7;

    if (data.size() < kHeaderSize) {
        Logger::Warning("Server: Transport datagram too short ("
                        + std::to_string(data.size()) + " bytes)");
        return;
    }

    const std::uint32_t receiver_index = ReadLE32(data.data() + 1);
    const std::uint16_t ip_len         = ReadLE16(data.data() + 5);

    if (data.size() < kHeaderSize + ip_len) {
        Logger::Warning("Server: Transport length field ("
                        + std::to_string(ip_len) + ") exceeds datagram");
        return;
    }

    if (ip_len < 20) {
        Logger::Warning("Server: Transport payload too short for IPv4 header ("
                        + std::to_string(ip_len) + ")");
        return;
    }

    // Validate this index belongs to an active session
    auto* session = session_manager_.Lookup(receiver_index);
    if (!session) {
        Logger::Warning("Server: Transport with unknown receiver_index "
                        + std::to_string(receiver_index)
                        + " from " + FormatEndpoint(sender));
        return;
    }

    ConstData ip_pkt{data.data() + kHeaderSize, ip_len};

    if (!tun_.IsOpen()) {
        Logger::Warning("Server: Transport received but TUN not open — packet dropped");
        return;
    }

    if (tun_.Write(ip_pkt) != static_cast<core::network::BytesTransferred>(ip_len)) {
        Logger::Error("Server: TUN write failed for " + std::to_string(ip_len) + " byte packet");
    } else {
        Logger::Debug("Server: Forwarded " + std::to_string(ip_len)
                      + " bytes from " + FormatEndpoint(sender) + " to TUN");
    }
}

// =========================================================================
// HandleTunReadable
// =========================================================================
//
// An IP response has arrived from the internet via the TUN device.
// Wrap it in a transport frame and send to the peer.

void Server::HandleTunReadable() {
    auto n = tun_.Read(tun_buf_);
    if (n <= 0) return;

    const auto ip_len = static_cast<std::size_t>(n);

    // Need an active session to know where to send
    if (active_local_index_ == 0) {
        Logger::Warning("Server: TUN readable but no active session — packet dropped");
        return;
    }
    auto* session = session_manager_.Lookup(active_local_index_);
    if (!session) {
        Logger::Warning("Server: TUN readable but session gone — packet dropped");
        return;
    }

    // Build plaintext transport frame
    // [type 1B][receiver_index 4B LE][length 2B LE][raw IP packet]
    static constexpr std::size_t kHeaderSize = 7;
    if (ip_len > tun_buf_.size() - kHeaderSize) {
        Logger::Warning("Server: TUN packet too large to frame ("
                        + std::to_string(ip_len) + ")");
        return;
    }

    // Shift IP packet right to make room for the 7-byte header in-place.
    // tun_buf_ has 4096 bytes; ip_len <= 4096 - 7 = 4089.
    std::memmove(tun_buf_.data() + kHeaderSize, tun_buf_.data(), ip_len);

    tun_buf_[0] = static_cast<std::uint8_t>(MessageType::Transport);
    WriteLE32(tun_buf_.data() + 1, session->receiver_index);
    WriteLE16(tun_buf_.data() + 5, static_cast<std::uint16_t>(ip_len));

    const std::size_t frame_len = kHeaderSize + ip_len;
    Data frame{tun_buf_.data(), frame_len};

    if (socket_.SendTo(peer_endpoint_, frame) < 0) {
        Logger::Error("Server: Failed to send TUN response to "
                      + FormatEndpoint(peer_endpoint_));
    } else {
        Logger::Debug("Server: Forwarded " + std::to_string(ip_len)
                      + " byte TUN response to " + FormatEndpoint(peer_endpoint_));
    }
}

// =========================================================================
// TimerTick — rekey / expiry housekeeping
// =========================================================================

void Server::TimerTick() {
    if (active_local_index_ == 0) return;

    auto* session = session_manager_.Lookup(active_local_index_);
    if (!session) return;

    const auto age = std::chrono::system_clock::now() - session->created;

    if (age >= kRejectAfterTime) {
        Logger::Warning("Server: Session expired (age="
                        + std::to_string(
                            std::chrono::duration_cast<std::chrono::seconds>(age).count())
                        + "s) — removing. Client must re-handshake.");
        session_manager_.Remove(active_local_index_);
        active_local_index_ = 0;
        return;
    }

    if (age >= kRekeyAfterTime) {
        Logger::Info("Server: Session rekey due (age="
                     + std::to_string(
                         std::chrono::duration_cast<std::chrono::seconds>(age).count())
                     + "s) — waiting for client to initiate new handshake");
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

std::string Server::FormatEndpoint(const Endpoint& ep) {
    return ep.ip.ToString() + ":" + std::to_string(ep.port);
}

void Server::CleanupResources() {
    if (tun_.IsOpen())    tun_.Close();
    if (poller_.IsOpen()) poller_.Close();
    if (socket_.IsOpen()) socket_.Close();
}

} // namespace server
