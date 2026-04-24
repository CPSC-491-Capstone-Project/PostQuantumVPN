#include "client.hpp"
#include "ipv4.hpp"
#include "logger.hpp"
#include "handshake_helpers.hpp"
#include "x25519.hpp"

#include <cstring>

#ifndef _WIN32
#include <sys/socket.h>
#endif

namespace client {

using core::utils::Logger;
using core::network::IPv4;
using core::handshake::ConsumeMessageResponse;
using core::handshake::CreateMessageInitiation;
using core::handshake::DeriveSessionKeys;
using core::handshake::DeriveMac1Key;
using core::handshake::DeserializeTransport;
using core::handshake::SerializeTransport;
using core::handshake::TransportDataMsg;
using core::session::SessionSecrets;

// =========================================================================
// Destructor
// =========================================================================

Client::~Client() {
    Shutdown();
}

// =========================================================================
// Builder setters
// =========================================================================

Client& Client::SetTunInterface(std::string_view ifname) {
    tun_ifname_ = ifname;
    return *this;
}

Client& Client::SetStaticKeys(
    const core::cryptography::x25519::PrivateKey& x25519_priv,
    const core::cryptography::x25519::PublicKey&  x25519_pub,
    const std::array<std::uint8_t, 2400>&         mlkem_dk,
    const std::array<std::uint8_t, 1184>&          mlkem_ek)
{
    local_x25519_priv_ = x25519_priv;
    local_x25519_pub_  = x25519_pub;
    local_mlkem_dk_    = mlkem_dk;
    local_mlkem_ek_    = mlkem_ek;
    return *this;
}

Client& Client::SetServerStaticKeys(
    const core::cryptography::x25519::PublicKey& server_x25519_pub,
    const std::array<std::uint8_t, 1184>&         server_mlkem_ek)
{
    server_x25519_pub_ = server_x25519_pub;
    server_mlkem_ek_   = server_mlkem_ek;
    return *this;
}

// =========================================================================
// Init
// =========================================================================

bool Client::Init(const std::string& server_ip, std::uint16_t server_port) {
    if (initialized_) {
        Logger::Warning("Client: Init called on already-initialized client");
        return false;
    }

    IPv4 ip{server_ip};
    if (!ip.IsValid()) {
        Logger::Error("Client: Invalid server IP: " + server_ip);
        return false;
    }
    server_endpoint_ = Endpoint{ip, server_port};

    // Open socket but do not bind — the OS assigns an ephemeral port on first SendTo.
    if (!socket_.Open()) {
        Logger::Error("Client: Failed to open UDP socket");
        return false;
    }

    // SO_MARK prevents VPN UDP packets from re-entering the TUN and causing a loop.
#ifdef SO_MARK
    {
        const std::uint32_t mark = 51820;
        if (setsockopt(socket_.GetHandle(), SOL_SOCKET, SO_MARK,
                       &mark, sizeof(mark)) != 0) {
            Logger::Warning("Client: Failed to set SO_MARK (requires CAP_NET_ADMIN)");
        } else {
            Logger::Info("Client: SO_MARK = 51820 set on UDP socket");
        }
    }
#endif

    if (!socket_.SetNonBlocking()) {
        Logger::Error("Client: Failed to set socket non-blocking");
        socket_.Close();
        return false;
    }

    if (!poller_.Open()) {
        Logger::Error("Client: Failed to create event poller");
        socket_.Close();
        return false;
    }
    if (!poller_.Add(socket_.GetHandle(), EventMask::Readable)) {
        Logger::Error("Client: Failed to register socket with poller");
        poller_.Close();
        socket_.Close();
        return false;
    }

    // TUN device — requires root/CAP_NET_ADMIN. Degrade gracefully if unavailable.
    if (!TunDevice::HasRequiredPrivileges()) {
        Logger::Warning("Client: Insufficient privileges for TUN — running without TUN");
    } else if (!tun_.Open(tun_ifname_)) {
        Logger::Warning("Client: Failed to open TUN device " + tun_ifname_ +
                        " — running without TUN");
    } else {
        tun_.SetNonBlocking();
        if (!poller_.Add(tun_.GetHandle(), EventMask::Readable)) {
            Logger::Error("Client: Failed to register TUN with poller");
            tun_.Close();
            poller_.Close();
            socket_.Close();
            return false;
        }
        use_tun_ = true;
        Logger::Info("Client: TUN interface " + tun_ifname_ + " registered");
    }

    initialized_ = true;
    Logger::Info("Client: Initialized, server = " + server_ip + ":" +
                 std::to_string(server_port));
    return true;
}

// =========================================================================
// Run / Stop / Shutdown
// =========================================================================

void Client::Run() {
    if (!initialized_ || stopped_) {
        Logger::Warning("Client: Run skipped (not initialized or stopped)");
        return;
    }

    running_.store(true, std::memory_order_relaxed);
    last_stats_time_ = std::chrono::steady_clock::now();
    Logger::Info("Client: Entering event loop");

    SendInitiation();

    std::array<PollEvent, 4> events{};

    while (running_.load(std::memory_order_relaxed)) {
        const int count = poller_.Poll(events, 250);

        if (count < 0) {
            Logger::Error("Client: Poll error — exiting");
            break;
        }

        for (int i = 0; i < count; ++i) {
            const auto& ev = events[static_cast<std::size_t>(i)];

            if (ev.IsError() || ev.IsHangup()) {
                Logger::Error("Client: Error/Hangup on fd " +
                              std::to_string(ev.handle));
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
                    case MessageType::Initiation:
                        HandleInitiation(payload, result->sender); break;
                    case MessageType::Response:
                        HandleResponse(payload, result->sender);   break;
                    case MessageType::Cookie:
                        HandleCookie(payload, result->sender);     break;
                    case MessageType::Transport:
                        HandleTransport(payload, result->sender);  break;
                    default:
                        Logger::Warning("Client: Unknown msg type " +
                                        std::to_string(recv_buffer_[0]));
                        break;
                }
            } else if (use_tun_ && tun_.IsOpen() &&
                       ev.handle == tun_.GetHandle()) {
                HandleTunRead();
            }
        }

        TimerTick();
    }

    Logger::Info("Client: Exiting event loop");
}

void Client::Stop() {
    stopped_ = true;
    running_.store(false, std::memory_order_relaxed);
    Logger::Info("Client: Stop requested");
}

void Client::Shutdown() {
    Stop();
    if (use_tun_) tun_.Close();
    poller_.Close();
    socket_.Close();
    initialized_ = false;
    stopped_      = false;
    use_tun_      = false;
    Logger::Info("Client: Shutdown complete");
}

// =========================================================================
// SendInitiation — build and send a Type 1 handshake message
// =========================================================================

void Client::SendInitiation() {
    // Reset peer to a clean slate, populate local and remote key material.
    peer_.Clear();
    peer_.local_static_x25519_private = local_x25519_priv_;
    peer_.local_static_x25519_public  = local_x25519_pub_;
    peer_.local_static_mlkem_dk       = local_mlkem_dk_;
    peer_.local_static_mlkem_ek       = local_mlkem_ek_;
    peer_.remote_static_x25519        = server_x25519_pub_;
    peer_.remote_static_mlkem_ek      = server_mlkem_ek_;
    peer_.endpoint_ip                 = server_endpoint_.ip;
    peer_.endpoint_port               = server_endpoint_.port;

    // Precompute static-static DH(client_static_priv, server_static_pub).
    auto ss = core::cryptography::x25519::DeriveSharedSecret(
        local_x25519_priv_, server_x25519_pub_);
    if (!ss) {
        Logger::Error("Client: SendInitiation — DeriveSharedSecret failed");
        return;
    }
    peer_.precomputed_static_static = *ss;

    // Derive mac1 key from server's static X25519 public key.
    auto mac1_key = DeriveMac1Key(
        core::utils::ConstByteSpan{server_x25519_pub_.data(), server_x25519_pub_.size()});
    if (!mac1_key) {
        Logger::Error("Client: SendInitiation — DeriveMac1Key failed");
        return;
    }
    peer_.mac1_key = *mac1_key;

    auto initiation = CreateMessageInitiation(peer_, index_table_);
    if (!initiation) {
        Logger::Error("Client: SendInitiation — CreateMessageInitiation failed");
        return;
    }

    Data wire{initiation->data(), initiation->size()};
    socket_.SendTo(server_endpoint_, wire);
    Logger::Info("Client: Initiation sent (" + std::to_string(initiation->size()) + " bytes)");
}

// =========================================================================
// HandleInitiation — server should never send us an initiation
// =========================================================================

void Client::HandleInitiation(ConstData /*data*/, const Endpoint& sender) {
    Logger::Debug("Client: Unexpected Initiation from " + FormatEndpoint(sender) + " — ignoring");
}

// =========================================================================
// HandleResponse — complete the handshake and activate the session
// =========================================================================

void Client::HandleResponse(ConstData data, const Endpoint& sender) {
    // Logger::Debug("Client: Response (" + std::to_string(data.size()) +
    //               " bytes) from " + FormatEndpoint(sender));

    if (data.size() < core::handshake::kResponseSize) {
        Logger::Warning("Client: Response too short: " + std::to_string(data.size()));
        return;
    }

    if (!ConsumeMessageResponse(
            core::utils::ConstByteSpan{data.data(), data.size()},
            peer_, index_table_)) {
        Logger::Warning("Client: ConsumeMessageResponse failed — handshake corrupted");
        return;
    }

    if (!DeriveSessionKeys(peer_, index_table_, true)) {
        Logger::Error("Client: DeriveSessionKeys failed");
        return;
    }

    // Initiator path: keypair lands in Current slot.
    auto* kp = peer_.keypairs.Current();
    if (!kp) {
        Logger::Error("Client: Keypair missing after DeriveSessionKeys");
        return;
    }

    SessionSecrets secrets;
    secrets.send_key       = kp->send_key;
    secrets.recv_key       = kp->receive_key;
    secrets.sender_index   = kp->local_index;
    secrets.receiver_index = kp->remote_index;
    secrets.is_initiator   = true;

    Session* session = sessions_.ActivateSession(secrets, sender);
    if (!session) {
        Logger::Error("Client: ActivateSession failed");
        return;
    }

    active_session_index_ = secrets.sender_index;
    has_session_          = true;

    Logger::Info("Client: Session established  local_idx=" + std::to_string(secrets.sender_index) +
                 "  remote_idx=" + std::to_string(secrets.receiver_index));
}

// =========================================================================
// HandleCookie
// =========================================================================

void Client::HandleCookie(ConstData /*data*/, const Endpoint& sender) {
    Logger::Debug("Client: Cookie from " + FormatEndpoint(sender) + " — not implemented");
}

// =========================================================================
// HandleTransport — decrypt and write into TUN
// =========================================================================

void Client::HandleTransport(ConstData data, const Endpoint& /*sender*/) {
    auto msg = DeserializeTransport(data.data(), data.size());
    if (!msg) {
        Logger::Warning("Client: Bad Transport header");
        return;
    }

    Session* session = sessions_.Lookup(msg->receiver_index);
    if (!session) {
        Logger::Warning("Client: No session for receiver_index=" +
                        std::to_string(msg->receiver_index));
        return;
    }

    ConstData payload{msg->encrypted_payload.data(), msg->encrypted_payload.size()};
    auto plaintext = session->Open(msg->counter, payload);
    if (!plaintext) {
        Logger::Warning("Client: Decrypt failed  receiver_index=" +
                        std::to_string(msg->receiver_index));
        return;
    }

    // Keepalive — empty plaintext, nothing to write to TUN
    if (plaintext->empty()) return;

    if (!use_tun_ || !tun_.IsOpen()) {
        Logger::Warning("Client: HandleTransport — TUN not available");
        return;
    }

    ConstData ip_pkt{plaintext->data(), plaintext->size()};
    tun_.Write(ip_pkt);
    bytes_recv_.fetch_add(plaintext->size(), std::memory_order_relaxed);
}

// =========================================================================
// HandleTunRead — encrypt and send a Transport message to the server
// =========================================================================

void Client::HandleTunRead() {
    Data buf{tun_buffer_.data(), tun_buffer_.size()};
    const BytesTransferred n = tun_.Read(buf);
    if (n <= 0) return;

    if (!has_session_) {
        Logger::Debug("Client: TUN read — no session yet, dropping packet");
        return;
    }

    Session* session = sessions_.Lookup(active_session_index_);
    if (!session) {
        Logger::Warning("Client: TUN read — active session not found");
        has_session_ = false;
        return;
    }

    ConstData pkt{tun_buffer_.data(), static_cast<std::size_t>(n)};
    SendTransport(*session, pkt);
}

// =========================================================================
// SendTransport — encrypt and send via UDP
// =========================================================================

void Client::SendTransport(Session& session, ConstData plaintext) {
    auto sealed = session.Seal(plaintext);
    if (!sealed) {
        Logger::Warning("Client: Seal failed for session " +
                        std::to_string(session.sender_index));
        return;
    }

    const std::uint64_t counter = session.send_nonce.load(std::memory_order_relaxed) - 1;

    TransportDataMsg msg;
    msg.receiver_index    = session.receiver_index;
    msg.counter           = counter;
    msg.encrypted_payload = std::move(*sealed);

    auto wire = SerializeTransport(msg);
    Data wire_span{wire.data(), wire.size()};
    socket_.SendTo(server_endpoint_, wire_span);
    session.last_sent_time = std::chrono::steady_clock::now();
    bytes_sent_.fetch_add(plaintext.size(), std::memory_order_relaxed);
}

// =========================================================================
// TimerTick — keepalives, session expiry, rekey trigger
// =========================================================================

void Client::TimerTick() {
    // Per-second stats
    auto now = std::chrono::steady_clock::now();
    if (now - last_stats_time_ >= std::chrono::seconds(1)) {
        const std::uint64_t tx = bytes_sent_.exchange(0, std::memory_order_relaxed);
        const std::uint64_t rx = bytes_recv_.exchange(0, std::memory_order_relaxed);
        Logger::Info("Client: TX=" + std::to_string(tx) + "B  RX=" + std::to_string(rx) + "B");
        last_stats_time_ = now;
    }

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
        socket_.SendTo(server_endpoint_, d);
        s->last_sent_time = std::chrono::steady_clock::now();
    }

    // Expire old sessions; if the active session expired, re-initiate
    const std::size_t swept = sessions_.SweepExpired();
    if (swept > 0) {
        Logger::Info("Client: Swept " + std::to_string(swept) + " expired sessions");
        if (has_session_ && sessions_.Lookup(active_session_index_) == nullptr) {
            Logger::Info("Client: Active session expired — re-initiating handshake");
            has_session_ = false;
            SendInitiation();
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================

std::string Client::FormatEndpoint(const Endpoint& ep) {
    return ep.ip.ToString() + ":" + std::to_string(ep.port);
}

} // namespace client
