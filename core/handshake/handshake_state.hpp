#ifndef _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_
#define _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_

#include "handshake_constants.hpp"
#include "tai64n.hpp"
#include <array>
#include <cstdint>
#include <mutex>

namespace core::handshake {

// The five states a handshake can be in
enum class HandshakeStateEnum : std::uint8_t {
    Zeroed             = 0,
    InitiationCreated  = 1,
    InitiationConsumed = 2,
    ResponseCreated    = 3,
    ResponseConsumed   = 4
};

struct HandshakeState {

    HandshakeStateEnum state{HandshakeStateEnum::Zeroed};

    Blake3Hash chaining_key{};
    Blake3Hash hash{};

    // Ephemeral keys for this handshake session
    std::array<std::uint8_t, 32>   local_ephemeral_x25519_private{};
    std::array<std::uint8_t, 32>   local_ephemeral_x25519_public{};
    std::array<std::uint8_t, 2400> local_ephemeral_mlkem_dk{};
    std::array<std::uint8_t, 1184> local_ephemeral_mlkem_ek{};

    // Peer keys from configuration
    std::array<std::uint8_t, 32>   remote_static_x25519{};
    std::array<std::uint8_t, 1184> remote_static_mlkem{};

    // Peer ephemeral keys extracted from received messages
    std::array<std::uint8_t, 32>   remote_ephemeral_x25519{};
    std::array<std::uint8_t, 1184> remote_ephemeral_mlkem{};

    // Precomputed X25519(our_static, their_static) to save one multiplication per handshake
    std::array<std::uint8_t, 32> precomputed_static_static{};

    // Optional PSK, all zeros if not configured
    std::array<std::uint8_t, 32> preshared_key{};

    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};

    std::array<std::uint8_t, 12> last_timestamp{};

    std::chrono::system_clock::time_point last_initiation_consumption{};
    std::chrono::system_clock::time_point last_sent_handshake{};

    // Protects concurrent access from event loop and timers
    mutable std::mutex mutex;

    // Zeros all sensitive fields and resets to Zeroed state
    void Clear() {
        state = HandshakeStateEnum::Zeroed;

        volatile std::uint8_t* p;

        p = chaining_key.data();
        for (std::size_t i = 0; i < chaining_key.size(); i++) p[i] = 0;

        p = hash.data();
        for (std::size_t i = 0; i < hash.size(); i++) p[i] = 0;

        p = local_ephemeral_x25519_private.data();
        for (std::size_t i = 0; i < local_ephemeral_x25519_private.size(); i++) p[i] = 0;

        p = local_ephemeral_mlkem_dk.data();
        for (std::size_t i = 0; i < local_ephemeral_mlkem_dk.size(); i++) p[i] = 0;

        p = preshared_key.data();
        for (std::size_t i = 0; i < preshared_key.size(); i++) p[i] = 0;

        local_index  = 0;
        remote_index = 0;
        last_timestamp.fill(0);
    }
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_