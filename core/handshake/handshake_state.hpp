#ifndef _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_
#define _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_

#include "handshake_constants.hpp"
#include "secure_memory.hpp"
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
    std::array<std::uint8_t, kMlKemDecapsulationKeyBytes> local_ephemeral_mlkem_dk{};
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
        using core::utils::secure_zero;

        state = HandshakeStateEnum::Zeroed;

        secure_zero(chaining_key);
        secure_zero(hash);

        secure_zero(local_ephemeral_x25519_private);
        secure_zero(local_ephemeral_x25519_public);
        secure_zero(local_ephemeral_mlkem_dk);
        secure_zero(local_ephemeral_mlkem_ek);

        secure_zero(remote_static_x25519);
        secure_zero(remote_static_mlkem);
        secure_zero(remote_ephemeral_x25519);
        secure_zero(remote_ephemeral_mlkem);

        secure_zero(precomputed_static_static);
        secure_zero(preshared_key);

        local_index  = 0;
        remote_index = 0;
        last_timestamp.fill(0);
    }
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_HANDSHAKE_STATE_HPP_