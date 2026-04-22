#include "client.hpp"
#include "ipv4.hpp"
#include "logger.hpp"

namespace client {

using core::utils::Logger;
using core::network::IPv4;

// =========================================================================
// Destructor
// =========================================================================

Client::~Client() {
    Shutdown();
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
    poller_.Close();
    socket_.Close();
    initialized_ = false;
    stopped_     = false;
    Logger::Info("Client: Shutdown complete");
}

// =========================================================================
// Stubs — log and return
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

void Client::HandleTransport(ConstData data, const Endpoint& sender) {
    (void)data; (void)sender;
    Logger::Info("Client: HandleTransport stub — no-op");
}

void Client::TimerTick() {
    // empty stub
}

} // namespace client
