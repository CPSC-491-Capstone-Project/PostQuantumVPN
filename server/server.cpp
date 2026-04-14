
#include "server.hpp"
#include "logger.hpp"
 
#include <string>


namespace server {

    using core::utils::Logger;
 
    // =========================================================================
    // Lifecycle
    // =========================================================================

    Server::~Server() {
        Shutdown();
    }
 
    // =========================================================================
    // Builder setters
    // =========================================================================
 
    Server& Server::SetBindAddress(IPv4 ip) {
        bind_ip_ = ip;
        return *this;
    }
 
    Server& Server::SetPort(Port port) {
        port_ = port;
        return *this;
    }
 
    Server& Server::SetPollTimeoutMs(int timeout_ms) {
        poll_timeout_ms_ = timeout_ms;
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
 
        // --- Open socket ---------------------------------------------------
        if (!socket_.Open()) {
            Logger::Error("Server: Failed to open UDP socket");
            return false;
        }
 
        // --- Bind -----------------------------------------------------------
        if (!socket_.Bind(bind_ip_, port_)) {
            Logger::Error("Server: Failed to bind to " + bind_ip_.ToString() + ":" + std::to_string(port_));
            CleanupResources();
            return false;
        }
 
        // --- Non-blocking ---------------------------------------------------
        if (!socket_.SetNonBlocking()) {
            Logger::Error("Server: Failed to set socket non-blocking");
            CleanupResources();
            return false;
        }
 
        // --- Poller ---------------------------------------------------------
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
 
        initialized_ = true;
        Logger::Info("Server: Initialized on " + bind_ip_.ToString() + ":" + std::to_string(port_));
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

        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }

        CleanupResources();
        initialized_ = false;
        stopped_ = false;
        Logger::Info("Server: Shutdown complete");
    }
 
    // =========================================================================
    // Event loop
    // =========================================================================
 
    void Server::EventLoop() {
        Logger::Info("Server: Entering event loop");
 
        // TODO: Add handling for multiple connections
        std::array<PollEvent, 4> events{};
 
        while (running_.load(std::memory_order_relaxed)) {
            int count = poller_.Poll(events, poll_timeout_ms_);
 
            if (count < 0) {
                Logger::Error("Server: Poll returned error, breaking loop");
                break;
            }
 
            for (int i = 0; i < count; ++i) {
                const auto& ev = events[static_cast<std::size_t>(i)];
 
                // --- Error / hangup on the socket ---
                if (ev.IsError() || ev.IsHangup()) {
                    Logger::Error("Server: Error/Hangup on handle " + std::to_string(ev.handle));
                    running_.store(false, std::memory_order_relaxed);
                    break;
                }
 
                // --- Readable: receive and dispatch ---
                if (ev.IsReadable()) {
                    auto result = socket_.ReceiveFrom(recv_buffer_);
                    if (!result) {
                        continue;
                    }
 
                    const auto bytes = result->bytes_read;
                    if (bytes == 0) {
                        continue;
                    }
 
                    // Payload view for handlers
                    Data payload{ recv_buffer_.data(), bytes };
 
                    // Byte 0 is the message type
                    const auto type = static_cast<MessageType>(recv_buffer_[0]);
 
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
                            Logger::Warning("Server: Unknown message type " + std::to_string(recv_buffer_[0]) + " from " + FormatEndpoint(result->sender));
                            break;
                    }
                }
            }
 
            TimerTick();
        }
 
        Logger::Info("Server: Exiting event loop");
    }
 
    // =========================================================================
    // Stub handlers
    // =========================================================================
 
    void Server::HandleInitiation(ConstData data, const Endpoint& sender) {
        Logger::Debug("Server: HandleInitiation - " + std::to_string(data.size()) + " bytes from " + FormatEndpoint(sender));
    }
 
    void Server::HandleResponse(ConstData data, const Endpoint& sender) {
        Logger::Debug("Server: HandleResponse - " + std::to_string(data.size()) + " bytes from " + FormatEndpoint(sender));
    }
 
    void Server::HandleCookie(ConstData data, const Endpoint& sender) {
        Logger::Debug("Server: HandleCookie - " + std::to_string(data.size()) + " bytes from " + FormatEndpoint(sender));
    }
 
    void Server::HandleTransport(ConstData data, const Endpoint& sender) {
        Logger::Debug("Server: HandleTransport - " + std::to_string(data.size()) + " bytes from " + FormatEndpoint(sender));
    }
 
    // =========================================================================
    // Timer tick (stub)
    // =========================================================================
 
    void Server::TimerTick() {
        // Future: check rekey timers, send keepalives, expire sessions, etc.
    }
 
    // =========================================================================
    // Internal helpers
    // =========================================================================
 
    std::string Server::FormatEndpoint(const Endpoint& ep) {
        return ep.ip.ToString() + ":" + std::to_string(ep.port);
    }
 
    void Server::CleanupResources() {
        if (poller_.IsOpen()) {
            poller_.Close();
        }
        if (socket_.IsOpen()) {
            socket_.Close();
        }
    }
 
} // namespace server