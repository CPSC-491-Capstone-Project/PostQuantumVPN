#ifndef _PQVPN_CORE_SESSION_SESSION_HPP_
#define _PQVPN_CORE_SESSION_SESSION_HPP_

#include "bit_utils.hpp"
#include "chacha20_poly1305.hpp"
#include "replay_window.hpp"
#include "udp_socket.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace core::session {

using ConstByteSpan = core::utils::ConstByteSpan;

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

    // Timestamp of last successfully decrypted inbound packet
    std::chrono::steady_clock::time_point last_received_time{};

    // Inbound replay filter — single receive-loop access assumed
    ReplayWindow replay_window{};

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

    // Encrypts plaintext and atomically increments the outbound counter.
    // Returns [ciphertext || 16-byte tag] on success, nullopt if the counter
    // is exhausted (>= kRejectAfterMessages).
    [[nodiscard]] auto Seal(ConstByteSpan plaintext)
        -> std::optional<std::vector<std::uint8_t>>;

    // Decrypts an inbound packet using the counter from the Transport header.
    // Checks the replay window before decryption and marks the counter as seen
    // only after successful authentication. Returns nullopt on any failure
    // without modifying session state — a failed authentication is silent.
    [[nodiscard]] auto Open(std::uint64_t counter, ConstByteSpan ciphertext_with_tag)
        -> std::optional<std::vector<std::uint8_t>>;

private:
    // Encodes counter into a 12-byte ChaCha20 nonce (WireGuard convention:
    // bytes 0-3 are zero, bytes 4-11 are counter in little-endian).
    static auto CounterToNonce(std::uint64_t counter)
        -> core::cryptography::chacha20_poly1305::Nonce;
};

} // namespace core::session

#endif // _PQVPN_CORE_SESSION_SESSION_HPP_
