#include "server.hpp"
#include "logger.hpp"

#include <cstring>
#include <vector>

#ifndef _WIN32
#include <sys/socket.h>
#endif

namespace server {

using core::utils::Logger;

// =========================================================================
// Destructor
// =========================================================================

Server::~Server() {
    Shutdown();
}

// =========================================================================
// Builder setters
// =========================================================================

Server& Server::SetBindAddress(IPv4 ip)  { bind_ip_ = ip;         return *this; }
Server& Server::SetPort(Port port)       { port_    = port;        return *this; }
Server& Server::SetPollTimeoutMs(int ms) { poll_timeout_ms_ = ms;  return *this; }

Server& Server::SetTunInterface(std::string_view ifname, IPv4 tun_ip) {
    tun_ifname_ = ifname;
    tun_ip_     = tun_ip;
    use_tun_    = true;
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

    // Socket
    if (!socket_.Open()) {
        Logger::Error("Server: Failed to open UDP socket");
        return false;
    }
    if (!socket_.Bind(bind_ip_, port_)) {
        Logger::Error("Server: Failed to bind " + bind_ip_.ToString() + ":" +
                      std::to_string(port_));
        CleanupResources();
        return false;
    }
    if (!socket_.SetNonBlocking()) {
        Logger::Error("Server: Failed to set socket non-blocking");
        CleanupResources();
        return false;
    }

    // SO_MARK lets the server's own UDP replies bypass the client-side policy
    // routing rule (not fwmark 51820 → tun0) when both run on the same host.
#ifdef SO_MARK
    {
        const std::uint32_t mark = 51820;
        if (setsockopt(socket_.GetHandle(), SOL_SOCKET, SO_MARK,
                       &mark, sizeof(mark)) != 0) {
            Logger::Warning("Server: Failed to set SO_MARK (requires CAP_NET_ADMIN)");
        } else {
            Logger::Info("Server: SO_MARK = 51820 set on UDP socket");
        }
    }
#endif

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
            Logger::Warning("Server: Failed to open TUN device " + tun_ifname_ +
                            " — running without TUN");
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
            Logger::Info("Server: TUN interface " + tun_ifname_ + " at " +
                         tun_ip_.ToString());
        }
    }

    initialized_ = true;
    Logger::Info("Server: Initialized on " + bind_ip_.ToString() + ":" +
                 std::to_string(port_));
    return true;
}

// =========================================================================
// Run / Stop / Shutdown
// =========================================================================

bool Server::Run() {
    if (!initialized_)  { Logger::Error("Server: Run called before Init");   return false; }
    if (stopped_)        { Logger::Warning("Server: Run called after Stop");  return false; }
    if (running_.load()) { Logger::Warning("Server: Already running");        return false; }

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

                if (type == MessageType::Transport) {
                    HandleTransport(payload, result->sender);
                } else {
                    Logger::Warning("Server: Ignoring non-Transport msg type " +
                                    std::to_string(recv_buffer_[0]) + " from " +
                                    FormatEndpoint(result->sender));
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
// HandleTransport — strip 7-byte header, forward raw IP to TUN
// Framing: [0x04 (1)] [receiver_index (4 LE)] [length (2 LE)] [raw IP]
// =========================================================================

void Server::HandleTransport(ConstData data, const Endpoint& sender) {
    constexpr std::size_t kHeaderSize = 7;
    if (data.size() < kHeaderSize) {
        Logger::Warning("Server: Transport too short (" + std::to_string(data.size()) +
                        " bytes) from " + FormatEndpoint(sender));
        return;
    }

    const std::uint16_t ip_len =
        static_cast<std::uint16_t>(data[5]) |
        (static_cast<std::uint16_t>(data[6]) << 8);

    if (data.size() < kHeaderSize + ip_len) {
        Logger::Warning("Server: Transport length field exceeds datagram from " +
                        FormatEndpoint(sender));
        return;
    }

    ConstData ip_pkt{data.data() + kHeaderSize, ip_len};

    // Learn client VPN IP for reverse routing (TUN → client)
    if (ip_len >= 20) {
        auto src_ip = TunDevice::ParseSrcIP(ip_pkt);
        if (src_ip) {
            std::lock_guard lock(routing_mutex_);
            ip_to_client_[src_ip->ToHostOrder()] = sender;
        }
    }

    if (!use_tun_ || !tun_.IsOpen()) return;
    if (ip_len < 20) return;

    tun_.Write(ip_pkt);
    Logger::Debug("Server: TUN <- " + std::to_string(ip_len) + " bytes from " +
                  FormatEndpoint(sender));
}

// =========================================================================
// HandleTunRead — wrap raw IP in 7-byte header, send to client via UDP
// =========================================================================

void Server::HandleTunRead() {
    Data buf{tun_buffer_.data(), tun_buffer_.size()};
    const BytesTransferred n = tun_.Read(buf);
    if (n <= 0) return;

    const auto ip_len = static_cast<std::size_t>(n);
    if (ip_len < 20) return;  // too short to be a valid IPv4 packet

    ConstData pkt{tun_buffer_.data(), ip_len};

    auto dst_ip = TunDevice::ParseDstIP(pkt);
    if (!dst_ip) return;

    Endpoint client_ep{};
    {
        std::lock_guard lock(routing_mutex_);
        auto it = ip_to_client_.find(dst_ip->ToHostOrder());
        if (it == ip_to_client_.end()) return;
        client_ep = it->second;
    }

    // Framing: [0x04][0x00 0x00 0x00 0x00][len LE][raw IP]
    const auto len16 = static_cast<std::uint16_t>(ip_len);
    std::vector<std::uint8_t> frame(7 + ip_len);
    frame[0] = 0x04;
    frame[1] = frame[2] = frame[3] = frame[4] = 0x00;
    frame[5] = static_cast<std::uint8_t>(len16);
    frame[6] = static_cast<std::uint8_t>(len16 >> 8);
    std::memcpy(frame.data() + 7, tun_buffer_.data(), ip_len);

    Data wire{frame.data(), frame.size()};
    socket_.SendTo(client_ep, wire);
    Logger::Debug("Server: UDP -> " + std::to_string(ip_len) + " bytes to " +
                  FormatEndpoint(client_ep));
}

// =========================================================================
// TimerTick
// =========================================================================

void Server::TimerTick() {}

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
