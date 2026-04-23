#ifndef _PQVPN_CORE_HANDSHAKE_PEER_HPP_
#define _PQVPN_CORE_HANDSHAKE_PEER_HPP_

#include "handshake_state.hpp"
#include "keypair.hpp"
#include "secure_memory.hpp"
#include "x25519.hpp"
#include "ipv4.hpp"
#include "network_constants.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace core::handshake {

// kMlKemDecapsulationKeyBytes / kMlKemEncapsulationKeyBytes defined in handshake_constants.hpp

struct Peer {

    // Local static identity
    core::cryptography::x25519::PrivateKey local_static_x25519_private{};
    core::cryptography::x25519::PublicKey  local_static_x25519_public{};
    std::array<std::uint8_t, kMlKemDecapsulationKeyBytes>  local_static_mlkem_dk{};
    std::array<std::uint8_t, kMlKemEncapsulationKeyBytes> local_static_mlkem_ek{};

    // Remote static keys (from config)
    core::cryptography::x25519::PublicKey  remote_static_x25519{};
    std::array<std::uint8_t, kMlKemEncapsulationKeyBytes> remote_static_mlkem_ek{};

    // Precomputed at construction
    core::cryptography::x25519::SharedSecret precomputed_static_static{}; // X25519(local_priv, remote_pub)
    Blake3Hash mac1_key{};    // BLAKE3("mac1----" || remote_static_x25519)
    Blake3Hash cookie_key{};  // BLAKE3("cookie--" || local_static_x25519_public)

    // Optional preshared key — all zeros if not configured
    std::array<std::uint8_t, 32> preshared_key{};

    // Network endpoint
    core::network::IPv4 endpoint_ip{};
    core::network::Port endpoint_port{0};

    // In-progress handshake — protected by handshake.mutex
    HandshakeState handshake{};

    // Session keypairs (current / previous / next)
    KeypairManager keypairs{};

    // Cookie state — protected by cookie_mutex
    std::array<std::uint8_t, 16>          last_received_cookie{};
    std::array<std::uint8_t, 16>          last_sent_mac1{};
    bool                                  cookie_valid{false};
    std::chrono::system_clock::time_point cookie_received_at{};
    mutable std::mutex                    cookie_mutex{};

    // Persistent counters
    std::uint32_t               handshake_retries{0};
    std::atomic<std::uint64_t>  tx_messages{0};
    std::atomic<std::uint64_t>  rx_messages{0};

    // Zeros all sensitive key material
    void Clear() {
        using core::utils::secure_zero;

        secure_zero(local_static_x25519_private);
        secure_zero(local_static_mlkem_dk);
        secure_zero(precomputed_static_static);
        secure_zero(preshared_key);
        secure_zero(mac1_key);
        secure_zero(cookie_key);
        secure_zero(last_received_cookie);
        secure_zero(last_sent_mac1);

        cookie_valid = false;
        handshake.Clear();
    }

    ~Peer() { Clear(); }

    Peer() = default;
    Peer(const Peer&)            = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&)                 = delete;
    Peer& operator=(Peer&&)      = delete;
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_PEER_HPP_
