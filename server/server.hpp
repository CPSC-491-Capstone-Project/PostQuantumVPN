#ifndef _PQVPN_SERVER_SERVER_HPP_
#define _PQVPN_SERVER_SERVER_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "ipv4.hpp"
#include "handshake_constants.hpp"

#include <atomic>
#include <string>
#include <thread>
#include <array>
#include <cstdint>

namespace server {

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
        
        // -----------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------
 
        /// Opens socket, binds, sets non-blocking, creates poller, registers
        /// the socket for readable events. Returns false on any failure and
        /// cleans up anything already opened.
        bool Init();
 
        /// Starts the event loop on a background thread.
        /// Returns false if Init() has not succeeded or if already running.
        bool Run();
 
        /// Signals the event loop to stop. Non-blocking — returns immediately.
        void Stop();
 
        /// Blocks until the background thread has joined, then closes the
        /// poller and socket. Safe to call multiple times.
        void Shutdown();

        // -----------------------------------------------------------------
        // Queries
        // -----------------------------------------------------------------
        [[nodiscard]] bool IsRunning() const { return running_.load(std::memory_order_relaxed); }
        [[nodiscard]] bool IsInitialized() const { return initialized_; }
 
        [[nodiscard]] const UDPSocket& GetSocket() const { return socket_; }
        [[nodiscard]] const EventPoller& GetPoller() const { return poller_; }

    private:

        // -----------------------------------------------------------------
        // Configuration (set via builder methods before Init)
        // -----------------------------------------------------------------
        IPv4 bind_ip_{};
        Port port_{};
        int poll_timeout_ms_{250};
 
        // -----------------------------------------------------------------
        // Runtime state
        // -----------------------------------------------------------------
        UDPSocket socket_{};
        EventPoller poller_{};
        std::array<std::uint8_t, 1500> recv_buffer_{};
 
        std::atomic<bool> running_{false};
        bool initialized_{false};
        std::thread worker_thread_{};


        // -----------------------------------------------------------------
        // Event loop (runs on worker_thread_)
        // -----------------------------------------------------------------
        void EventLoop();

        // -----------------------------------------------------------------
        // Message handlers
        // -----------------------------------------------------------------
        void HandleInitiation(ConstData data, const Endpoint& sender);
        void HandleResponse(ConstData data, const Endpoint& sender);
        void HandleCookie(ConstData data, const Endpoint& sender);
        void HandleTransport(ConstData data,const Endpoint& sender);

        /// Called once per poll iteration for periodic housekeeping
        void TimerTick();

        // -----------------------------------------------------------------
        // Internal helpers
        // -----------------------------------------------------------------
 
        /// Formats an Endpoint as "ip:port" for log messages.
        /// Keeps OS-specific formatting out of the server logic — delegates
        /// to Endpoint's existing string fields.
        static std::string FormatEndpoint(const Endpoint& ep);

        /// Closes whatever has been opened so far (poller, socket).
        /// Used for partial-failure cleanup inside Init() and by Shutdown().
        void CleanupResources();

    };

} // namespace server

#endif // _PQVPN_SERVER_SERVER_HPP_