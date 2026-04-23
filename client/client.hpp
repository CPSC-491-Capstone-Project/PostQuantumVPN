#ifndef _PQVPN_CLIENT_CLIENT_HPP_
#define _PQVPN_CLIENT_CLIENT_HPP_

#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "handshake_constants.hpp"
#include "handshake_messages.hpp"

#include <atomic>
#include <array>
#include <cstdint>
#include <string>

namespace client {

using core::network::UDPSocket;
using core::network::EventPoller;
using core::network::EventMask;
using core::network::PollEvent;
using core::network::Endpoint;
using core::network::ConstData;
using core::handshake::MessageType;

class Client {
public:
    Client() = default;
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&)                 = delete;
    Client& operator=(Client&&)      = delete;

    // Opens socket (no bind), sets non-blocking, stores server endpoint,
    // creates epoll, registers socket for Readable.
    bool Init(const std::string& server_ip, std::uint16_t server_port);

    // Calls SendInitiation() stub, then polls until Stop() is called.
    void Run();

    // Sets running_ = false; a subsequent Run() call returns immediately.
    void Stop();

    // Closes poller then socket.  Safe to call more than once.
    void Shutdown();

    [[nodiscard]] bool IsInitialized() const { return initialized_; }

private:
    UDPSocket   socket_{};
    EventPoller poller_{};
    std::array<std::uint8_t, 1500> recv_buffer_{};
    Endpoint    server_endpoint_{};
    std::atomic<bool> running_{false};

    bool initialized_{false};
    bool stopped_{false};

    // --- Stubs ---
    void SendInitiation();
    void HandleInitiation(ConstData data, const Endpoint& sender);
    void HandleResponse(ConstData data, const Endpoint& sender);
    void HandleCookie(ConstData data, const Endpoint& sender);
    void HandleTransport(ConstData data, const Endpoint& sender);
    void TimerTick();
};

} // namespace client

#endif // _PQVPN_CLIENT_CLIENT_HPP_
