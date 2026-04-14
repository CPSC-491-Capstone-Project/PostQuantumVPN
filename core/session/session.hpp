#ifndef _PQVPN_CORE_SESSION_SESSION_HPP_
#define _PQVPN_CORE_SESSION_SESSION_HPP_

#include "chacha20_poly1305.hpp"
#include "udp_socket.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>

namespace core::session {

// Output of the handshake KDF2(C, empty). The handshake module is responsible
// for placing the correct keys in the correct fields before calling
// SessionManager::ActivateSession — this struct does not know which role it is.
struct SessionSecrets {
    core::cryptography::chacha20_poly1305::Key send_key{};
    core::cryptography::chacha20_poly1305::Key recv_key{};
    std::uint32_t sender_index{0};    // local index assigned during handshake
    std::uint32_t receiver_index{0};  // remote peer's index
    bool is_initiator{false};
};

// An active session ready for packet encryption/decryption.
// Owned exclusively by SessionManager via unique_ptr.
struct Session {
    core::cryptography::chacha20_poly1305::Key send_key{};
    core::cryptography::chacha20_poly1305::Key recv_key{};

    // Incremented atomically per outgoing packet — must never wrap
    std::atomic<std::uint64_t> send_nonce{0};

    bool is_initiator{false};
    std::chrono::system_clock::time_point created{};

    std::uint32_t sender_index{0};
    std::uint32_t receiver_index{0};

    core::network::Endpoint peer{};

    // Zeros send and receive keys before destruction
    void Clear() {
        volatile std::uint8_t* p;

        p = send_key.data();
        for (std::size_t i = 0; i < send_key.size(); ++i) p[i] = 0;

        p = recv_key.data();
        for (std::size_t i = 0; i < recv_key.size(); ++i) p[i] = 0;
    }

    ~Session() { Clear(); }

    Session() = default;
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&)                 = delete;
    Session& operator=(Session&&)      = delete;
};

} // namespace core::session

#endif // _PQVPN_CORE_SESSION_SESSION_HPP_
