The client needs a process that can start, send and receive UDP datagrams, and shut down cleanly. This ticket creates the skeleton. Every handler is a stub that logs and returns — the only goal is a running process with a loop that can be filled in later.

Create client/client.hpp and client/client.cpp.

The Client class owns a core::network::UDPSocket, a core::network::EventPoller, a receive buffer (std::array<std::uint8_t, 1500>), a stored server core::network::Endpoint, and a std::atomic<bool> running_. The socket is opened but not bound — the OS assigns an ephemeral port on the first SendTo.

Init(const std::string& server_ip, std::uint16_t server_port) -> bool — opens socket, sets non-blocking, stores the server endpoint, creates the epoll instance, registers the socket handle for EventMask::Readable.

Run() — enters the main loop. Before the first Poll, calls a SendInitiation() stub that logs a message and returns. The loop body is the same pattern: Poll → ReceiveFrom → read byte 0 → dispatch to HandleInitiation, HandleResponse, HandleCookie, or HandleTransport stubs (all log and return). After processing events, call a TimerTick() stub (empty). Exit on IsError() / IsHangup().

Stop() — sets running_ = false. Shutdown() — closes poller then socket.

Tests:

Init with a loopback server endpoint succeeds; socket and poller are open.

Stop before Run — returns immediately.

Shutdown closes handles cleanly. Double Shutdown does not crash.


