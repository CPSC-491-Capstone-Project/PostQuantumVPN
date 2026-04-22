#include "client.hpp"
#include "ipv4.hpp"
#include "logger.hpp"

#include <cstring>
#include <vector>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace client {

using core::utils::Logger;
using core::network::IPv4;
using core::network::Data;

// =========================================================================
// Destructor
// =========================================================================

Client::~Client() {
    Shutdown();
}

// =========================================================================
// Builder setter
// =========================================================================

Client& Client::SetTunInterface(std::string_view ifname) {
    tun_ifname_ = ifname;
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

    // Open socket but do not bind — the OS assigns an ephemeral port on
    // the first SendTo.
    if (!socket_.Open()) {
        Logger::Error("Client: Failed to open UDP socket");
        return false;
    }

    // SO_MARK prevents the VPN's own UDP packets from re-entering the TUN
    // and causing a routing loop.  Requires CAP_NET_ADMIN on Linux.
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

    // Raw socket used to inject decapsulated inbound IP packets back into the
    // kernel via the OUTPUT path.  Packets destined for a local address (the
    // VPN tunnel IP) are looped back through INPUT and delivered to the waiting
    // application socket.  SO_MARK ensures non-local destinations use the main
    // routing table instead of being caught by Rule B (→ tun0 loop).
#ifndef _WIN32
    inject_fd_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (inject_fd_ < 0) {
        Logger::Warning("Client: Failed to open raw inject socket — inbound injection unavailable");
    } else {
        int one = 1;
        if (::setsockopt(inject_fd_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0)
            Logger::Warning("Client: Failed to set IP_HDRINCL on inject socket");
#ifdef SO_MARK
        const std::uint32_t mark = 51820;
        if (::setsockopt(inject_fd_, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
            Logger::Warning("Client: Failed to set SO_MARK on inject socket");
#endif
        Logger::Info("Client: Raw inject socket ready");
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

    // TUN device — requires root/CAP_NET_ADMIN.  Degrade gracefully if
    // unavailable so unit tests and non-root runs still work.
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
#ifndef _WIN32
    if (inject_fd_ >= 0) {
        ::close(inject_fd_);
        inject_fd_ = -1;
    }
#endif
    initialized_ = false;
    stopped_      = false;
    use_tun_      = false;
    Logger::Info("Client: Shutdown complete");
}

// =========================================================================
// TUN → UDP: read IP packet, wrap in framing header, send to server
// Framing: [0x04 (1)] [receiver_index (4 LE, 0 for plaintext)] [length (2 LE)] [raw IP]
// =========================================================================

void Client::HandleTunRead() {
    const auto n = tun_.Read(tun_buffer_);
    if (n <= 0) return;

    const auto ip_len = static_cast<std::size_t>(n);
    const auto len16  = static_cast<std::uint16_t>(ip_len);

    std::vector<std::uint8_t> frame(7 + ip_len);
    frame[0] = 0x04;
    frame[1] = frame[2] = frame[3] = frame[4] = 0x00;  // receiver_index = 0 (plaintext)
    frame[5] = static_cast<std::uint8_t>(len16);
    frame[6] = static_cast<std::uint8_t>(len16 >> 8);
    std::memcpy(frame.data() + 7, tun_buffer_.data(), ip_len);

    Data frame_data{frame.data(), frame.size()};
    socket_.SendTo(server_endpoint_, frame_data);
    Logger::Debug("Client: Forwarded " + std::to_string(ip_len) +
                  " byte IP packet to server");
}

// =========================================================================
// UDP → TUN: strip framing header, write raw IP packet into TUN
// =========================================================================

void Client::HandleTransport(ConstData data, const Endpoint& sender) {
    (void)sender;

    constexpr std::size_t kHeaderSize = 7;
    if (data.size() < kHeaderSize) {
        Logger::Warning("Client: HandleTransport — packet too short (" +
                        std::to_string(data.size()) + " bytes)");
        return;
    }

    const std::uint16_t ip_len =
        static_cast<std::uint16_t>(data[5]) |
        (static_cast<std::uint16_t>(data[6]) << 8);

    if (data.size() < kHeaderSize + ip_len) {
        Logger::Warning("Client: HandleTransport — length field exceeds datagram");
        return;
    }

    ConstData ip_payload{data.data() + kHeaderSize, ip_len};

#ifndef _WIN32
    if (inject_fd_ >= 0 && ip_len >= 20) {
        // Inject via raw socket — packet travels through OUTPUT/loopback path
        // and is delivered to the waiting app socket via INPUT.  This reliably
        // reaches the application regardless of policy routing rules on tun0.
        struct sockaddr_in dst{};
        dst.sin_family = AF_INET;
        std::memcpy(&dst.sin_addr.s_addr, ip_payload.data() + 16, 4);
        ::sendto(inject_fd_, ip_payload.data(), ip_len, 0,
                 reinterpret_cast<const struct sockaddr*>(&dst), sizeof(dst));
        Logger::Debug("Client: Injected " + std::to_string(ip_len) +
                      " byte IP packet via raw socket");
        return;
    }
#endif

    if (!use_tun_ || !tun_.IsOpen()) {
        Logger::Warning("Client: HandleTransport — no inject socket and TUN not available");
        return;
    }
    tun_.Write(ip_payload);
    Logger::Debug("Client: Wrote " + std::to_string(ip_len) +
                  " byte IP packet to TUN (fallback)");
}

// =========================================================================
// Remaining stubs — log and return
// =========================================================================

void Client::SendInitiation() {
    Logger::Info("Client: SendInitiation stub — no-op");
}

void Client::HandleInitiation(ConstData data, const Endpoint& sender) {
    (void)data; (void)sender;
    Logger::Info("Client: HandleInitiation stub — no-op");
}

void Client::HandleResponse(ConstData data, const Endpoint& sender) {
    (void)data; (void)sender;
    Logger::Info("Client: HandleResponse stub — no-op");
}

void Client::HandleCookie(ConstData data, const Endpoint& sender) {
    (void)data; (void)sender;
    Logger::Info("Client: HandleCookie stub — no-op");
}

void Client::TimerTick() {
    // empty stub
}

} // namespace client
