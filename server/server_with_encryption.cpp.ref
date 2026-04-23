
#include "server.hpp"
#include "logger.hpp"
#include "handshake_constants.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace server {

using core::utils::Logger;
using core::handshake::ConsumeMessageInitiation;
using core::handshake::CreateMessageResponse;
using core::handshake::DeriveSessionKeys;
using core::handshake::DeserializeTransport;
using core::handshake::SerializeTransport;
using core::handshake::TransportDataMsg;
using core::handshake::kInitiationSize;
using core::session::SessionSecrets;

// =========================================================================
// Destructor
// =========================================================================

Server::~Server() {
    Shutdown();
}

// =========================================================================
// Builder setters
// =========================================================================

Server& Server::SetBindAddress(IPv4 ip)          { bind_ip_ = ip;           return *this; }
Server& Server::SetPort(Port port)               { port_    = port;         return *this; }
Server& Server::SetPollTimeoutMs(int ms)         { poll_timeout_ms_ = ms;   return *this; }

Server& Server::SetTunInterface(std::string_view ifname, IPv4 tun_ip) {
    tun_ifname_ = ifname;
    tun_ip_     = tun_ip;
    use_tun_    = true;
    return *this;
}

Server& Server::SetStaticKeys(
    const core::cryptography::x25519::PrivateKey&  x25519_priv,
    const core::cryptography::x25519::PublicKey&   x25519_pub,
    const std::array<std::uint8_t, 2400>&           mlkem_dk,
    const std::array<std::uint8_t, 1184>&           mlkem_ek)
{
    local_x25519_priv_ = x25519_priv;
    local_x25519_pub_  = x25519_pub;
    local_mlkem_dk_    = mlkem_dk;
    local_mlkem_ek_    = mlkem_ek;
    return *this;
}

// =========================================================================
// Init
// =========================================================================

bool Server::Init() {
    if (initialized_) {
        Logger::Warning("Server: Init called on already-initialized server");
        return false;
    }

    if (!bind_ip_.IsValid()) {
        Logger::Error("Server: Bind address is invalid");
        return false;
    }

    const bool keys_zero = std::all_of(local_x25519_priv_.begin(), local_x25519_priv_.end(),
                                        [](std::uint8_t b){ return b == 0; });
    if (keys_zero) {
        Logger::Error("Server: Static keys not set — call SetStaticKeys before Init");
        return false;
    }

    // Socket
    if (!socket_.Open()) {
        Logger::Error("Server: Failed to open UDP socket");
        return false;
    }
    if (!socket_.Bind(bind_ip_, port_)) {
        Logger::Error("Server: Failed to bind " + bind_ip_.ToString() + ":" + std::to_string(port_));
        CleanupResources();
        return false;
    }
    if (!socket_.SetNonBlocking()) {
        Logger::Error("Server: Failed to set socket non-blocking");
        CleanupResources();
        return false;
    }

    // Poller
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

    // TUN device (optional — requires root/CAP_NET_ADMIN)
    if (use_tun_) {
        if (!TunDevice::HasRequiredPrivileges()) {
            Logger::Warning("Server: Insufficient privileges for TUN — running without TUN");
            use_tun_ = false;
        } else if (!tun_.Open(tun_ifname_)) {
            Logger::Warning("Server: Failed to open TUN device " + tun_ifname_ + " — running without TUN");
            use_tun_ = false;
        } else if (!tun_.BringUp(tun_ip_)) {
            Logger::Warning("Server: TUN BringUp failed — running without TUN");
            tun_.Close();
            use_tun_ = false;
        } else {
            tun_.SetNonBlocking();
            if (!poller_.Add(tun_.GetHandle(), EventMask::Readable)) {
                Logger::Error("Server: Failed to register TUN with poller");
                CleanupResources();
                return false;
            }
            Logger::Info("Server: TUN interface " + tun_ifname_ + " at " + tun_ip_.ToString());
        }
    }

    core::handshake::InitHandshakeConstants();

    initialized_ = true;
    Logger::Info("Server: Initialized on " + bind_ip_.ToString() + ":" + std::to_string(port_));
    return true;
}

// =========================================================================
// Run / Stop / Shutdown
// =========================================================================

bool Server::Run() {
    if (!initialized_) { Logger::Error("Server: Run called before Init");       return false; }
    if (stopped_)       { Logger::Warning("Server: Run called after Stop");      return false; }
    if (running_.load()) { Logger::Warning("Server: Already running");           return false; }

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
    stopped_     = false;
    Logger::Info("Server: Shutdown complete");
}

// =========================================================================
// Event loop
// =========================================================================

void Server::EventLoop() {
    Logger::Info("Server: Entering event loop");
    std::array<PollEvent, 8> events{};

    while (running_.load(std::memory_order_relaxed)) {
        const int count = poller_.Poll(events, poll_timeout_ms_);

        if (count < 0) {
            Logger::Error("Server: Poll error — exiting");
            break;
        }

        for (int i = 0; i < count; ++i) {
            const auto& ev = events[static_cast<std::size_t>(i)];

            if (ev.IsError() || ev.IsHangup()) {
                Logger::Error("Server: Error/Hangup on fd " + std::to_string(ev.handle));
                running_.store(false, std::memory_order_relaxed);
                break;
            }

            if (!ev.IsReadable()) continue;

            if (ev.handle == socket_.GetHandle()) {
                auto result = socket_.ReceiveFrom(recv_buffer_);
                if (!result || result->bytes_read == 0) continue;

                ConstData payload{recv_buffer_.data(), result->bytes_read};
                const auto type = static_cast<MessageType>(recv_buffer_[0]);

                switch (type) {
                    case MessageType::Initiation: HandleInitiation(payload, result->sender); break;
                    case MessageType::Response:   HandleResponse(payload, result->sender);   break;
                    case MessageType::Cookie:     HandleCookie(payload, result->sender);     break;
                    case MessageType::Transport:  HandleTransport(payload, result->sender);  break;
                    default:
                        Logger::Warning("Server: Unknown msg type " +
                                        std::to_string(recv_buffer_[0]) + " from " +
                                        FormatEndpoint(result->sender));
                        break;
                }
            } else if (use_tun_ && tun_.IsOpen() && ev.handle == tun_.GetHandle()) {
                HandleTunRead();
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
    Logger::Debug("Server: Initiation (" + std::to_string(data.size()) +
                  " bytes) from " + FormatEndpoint(sender));

    if (data.size() != kInitiationSize) {
        Logger::Warning("Server: Initiation size mismatch: " + std::to_string(data.size()));
        return;
    }

    // Fresh Peer with server's static keys; remote keys stay all-zeros → open-server mode
    auto peer = std::make_unique<Peer>();
    peer->local_static_x25519_private = local_x25519_priv_;
    peer->local_static_x25519_public  = local_x25519_pub_;
    peer->local_static_mlkem_dk       = local_mlkem_dk_;
    peer->local_static_mlkem_ek       = local_mlkem_ek_;
    peer->endpoint_ip                 = sender.ip;
    peer->endpoint_port               = sender.port;

    if (!ConsumeMessageInitiation(data, *peer)) {
        Logger::Warning("Server: ConsumeMessageInitiation failed from " + FormatEndpoint(sender));
        return;
    }

    auto response_bytes = CreateMessageResponse(*peer, index_table_);
    if (!response_bytes) {
        Logger::Error("Server: CreateMessageResponse failed");
        return;
    }

    Data resp_span{response_bytes->data(), response_bytes->size()};
    socket_.SendTo(sender, resp_span);

    if (!DeriveSessionKeys(*peer, index_table_, false)) {
        Logger::Error("Server: DeriveSessionKeys failed");
        return;
    }

    // Responder path: keypair lands in Next slot
    auto* kp = peer->keypairs.Next();
    if (!kp) {
        Logger::Error("Server: Keypair missing after DeriveSessionKeys");
        return;
    }

    SessionSecrets secrets;
    secrets.send_key       = kp->send_key;
    secrets.recv_key       = kp->receive_key;
    secrets.sender_index   = kp->local_index;
    secrets.receiver_index = kp->remote_index;
    secrets.is_initiator   = false;

    const std::uint32_t local_idx = kp->local_index;

    Session* session = sessions_.ActivateSession(secrets, sender);
    if (!session) {
        Logger::Error("Server: ActivateSession failed");
        return;
    }

    {
        std::lock_guard lock(peers_mutex_);
        peers_[local_idx] = std::move(peer);
    }

    Logger::Info("Server: Session established  peer=" + FormatEndpoint(sender) +
                 "  local_idx=" + std::to_string(local_idx) +
                 "  remote_idx=" + std::to_string(secrets.receiver_index));
}

// =========================================================================
// HandleResponse  (server is always responder — ignore)
// =========================================================================

void Server::HandleResponse(ConstData /*data*/, const Endpoint& sender) {
    Logger::Debug("Server: Unexpected Response from " + FormatEndpoint(sender) + " — ignoring");
}

// =========================================================================
// HandleCookie
// =========================================================================

void Server::HandleCookie(ConstData /*data*/, const Endpoint& sender) {
    Logger::Debug("Server: Cookie from " + FormatEndpoint(sender) + " — not implemented");
}

// =========================================================================
// HandleTransport  (decrypt and forward to TUN)
// =========================================================================

void Server::HandleTransport(ConstData data, const Endpoint& sender) {
    auto msg = DeserializeTransport(data.data(), data.size());
    if (!msg) {
        Logger::Warning("Server: Bad Transport from " + FormatEndpoint(sender));
        return;
    }

    Session* session = sessions_.Lookup(msg->receiver_index);
    if (!session) {
        Logger::Warning("Server: No session for receiver_index=" +
                        std::to_string(msg->receiver_index));
        return;
    }

    ConstData payload{msg->encrypted_payload.data(), msg->encrypted_payload.size()};
    auto plaintext = session->Open(msg->counter, payload);
    if (!plaintext) {
        Logger::Warning("Server: Decrypt failed  receiver_index=" +
                        std::to_string(msg->receiver_index));
        return;
    }

    // Keepalive — empty plaintext, nothing to forward
    if (plaintext->empty()) return;

    // Learn client VPN IP for reverse routing (TUN → client)
    if (plaintext->size() >= 20) {
        ConstData pkt{plaintext->data(), plaintext->size()};
        auto src_ip = TunDevice::ParseSrcIP(pkt);
        if (src_ip) {
            std::lock_guard lock(routing_mutex_);
            ip_to_session_[src_ip->ToHostOrder()] = msg->receiver_index;
        }
    }

    // Forward decrypted packet to the TUN kernel interface → internet
    if (use_tun_ && tun_.IsOpen()) {
        ConstData pkt{plaintext->data(), plaintext->size()};
        tun_.Write(pkt);
    }
}

// =========================================================================
// HandleTunRead  (read response from internet, encrypt and send to client)
// =========================================================================

void Server::HandleTunRead() {
    Data buf{tun_buffer_.data(), tun_buffer_.size()};
    const BytesTransferred n = tun_.Read(buf);
    if (n <= 0) return;

    ConstData pkt{tun_buffer_.data(), static_cast<std::size_t>(n)};
    if (pkt.size() < 20) return;  // too short to be a valid IPv4 packet

    auto dst_ip = TunDevice::ParseDstIP(pkt);
    if (!dst_ip) return;

    std::uint32_t session_idx = 0;
    {
        std::lock_guard lock(routing_mutex_);
        auto it = ip_to_session_.find(dst_ip->ToHostOrder());
        if (it == ip_to_session_.end()) return;
        session_idx = it->second;
    }

    Session* session = sessions_.Lookup(session_idx);
    if (!session) return;

    SendTransport(*session, pkt);
}

// =========================================================================
// SendTransport  (encrypt plaintext and send a Transport message via UDP)
// =========================================================================

void Server::SendTransport(Session& session, ConstData plaintext) {
    auto sealed = session.Seal(plaintext);
    if (!sealed) {
        Logger::Warning("Server: Seal failed for session " + std::to_string(session.sender_index));
        return;
    }

    // send_nonce was incremented by Seal(); the used counter is the previous value
    const std::uint64_t counter = session.send_nonce.load(std::memory_order_relaxed) - 1;

    TransportDataMsg msg;
    msg.receiver_index    = session.receiver_index;
    msg.counter           = counter;
    msg.encrypted_payload = std::move(*sealed);

    auto wire = SerializeTransport(msg);
    Data wire_span{wire.data(), wire.size()};
    socket_.SendTo(session.peer, wire_span);
    session.last_sent_time = std::chrono::steady_clock::now();
}

// =========================================================================
// TimerTick  (periodic housekeeping from the event loop)
// =========================================================================

void Server::TimerTick() {
    // Keepalives
    for (auto idx : sessions_.GetKeepaliveDue()) {
        Session* s = sessions_.Lookup(idx);
        if (!s) continue;
        auto ka = s->CreateKeepalive();
        if (!ka) continue;

        const std::uint64_t counter = s->send_nonce.load(std::memory_order_relaxed) - 1;
        TransportDataMsg msg;
        msg.receiver_index    = s->receiver_index;
        msg.counter           = counter;
        msg.encrypted_payload = std::move(*ka);
        auto wire = SerializeTransport(msg);
        Data d{wire.data(), wire.size()};
        socket_.SendTo(s->peer, d);
        s->last_sent_time = std::chrono::steady_clock::now();
    }

    // Expire old sessions
    if (const std::size_t n = sessions_.SweepExpired(); n > 0) {
        Logger::Info("Server: Swept " + std::to_string(n) + " expired sessions");
    }
}

// =========================================================================
// Helpers
// =========================================================================

std::string Server::FormatEndpoint(const Endpoint& ep) {
    return ep.ip.ToString() + ":" + std::to_string(ep.port);
}

void Server::CleanupResources() {
    if (use_tun_ && tun_.IsOpen()) tun_.Close();
    if (poller_.IsOpen())          poller_.Close();
    if (socket_.IsOpen())          socket_.Close();
}

} // namespace server
