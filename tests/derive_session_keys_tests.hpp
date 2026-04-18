#ifndef _PQVPN_TESTS_DERIVE_SESSION_KEYS_TESTS_HPP_
#define _PQVPN_TESTS_DERIVE_SESSION_KEYS_TESTS_HPP_

#include "test_utils.hpp"
#include "handshake_processor.hpp"
#include "handshake_messages.hpp"
#include "handshake_constants.hpp"
#include "peer.hpp"
#include "index_table.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <thread>
#include <vector>

using namespace core::handshake;

// ============================================================================
// Peer pair setup (mirrors SetupPeerPair from handshake_response_tests.hpp,
// but defined here so this file is self-contained)
// ============================================================================

struct DskPeerPair {
    Peer initiator{};
    Peer responder{};
};

static bool SetupDskPeerPair(DskPeerPair& pp) {
    auto init_x25519 = core::cryptography::x25519::GenerateKeyPair();
    if (!init_x25519) return false;

    auto init_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!init_mlkem) return false;

    auto resp_x25519 = core::cryptography::x25519::GenerateKeyPair();
    if (!resp_x25519) return false;

    auto resp_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!resp_mlkem) return false;

    // Initiator side
    pp.initiator.local_static_x25519_private = init_x25519->private_key;
    pp.initiator.local_static_x25519_public  = init_x25519->public_key;
    std::copy(init_mlkem->public_key.begin(), init_mlkem->public_key.end(),
              pp.initiator.local_static_mlkem_ek.begin());

    std::size_t init_dk_len = kMlKemDecapsulationKeyBytes;
    if (EVP_PKEY_get_raw_private_key(init_mlkem->pkey.get(),
                                     pp.initiator.local_static_mlkem_dk.data(),
                                     &init_dk_len) != 1)
        return false;

    pp.initiator.remote_static_x25519 = resp_x25519->public_key;
    std::copy(resp_mlkem->public_key.begin(), resp_mlkem->public_key.end(),
              pp.initiator.remote_static_mlkem_ek.begin());

    auto init_ss = core::cryptography::x25519::DeriveSharedSecret(
        init_x25519->private_key, resp_x25519->public_key);
    if (!init_ss) return false;
    pp.initiator.precomputed_static_static = *init_ss;

    // Responder side
    pp.responder.local_static_x25519_private = resp_x25519->private_key;
    pp.responder.local_static_x25519_public  = resp_x25519->public_key;
    std::copy(resp_mlkem->public_key.begin(), resp_mlkem->public_key.end(),
              pp.responder.local_static_mlkem_ek.begin());

    std::size_t resp_dk_len = kMlKemDecapsulationKeyBytes;
    if (EVP_PKEY_get_raw_private_key(resp_mlkem->pkey.get(),
                                     pp.responder.local_static_mlkem_dk.data(),
                                     &resp_dk_len) != 1)
        return false;

    pp.responder.remote_static_x25519 = init_x25519->public_key;
    std::copy(init_mlkem->public_key.begin(), init_mlkem->public_key.end(),
              pp.responder.remote_static_mlkem_ek.begin());

    auto resp_ss = core::cryptography::x25519::DeriveSharedSecret(
        resp_x25519->private_key, init_x25519->public_key);
    if (!resp_ss) return false;
    pp.responder.precomputed_static_static = *resp_ss;

    return true;
}

// ============================================================================
// Full handshake simulation
//
// Simulates two peers exchanging messages via in-memory buffers —
// no network I/O, but the complete 4-function sequence:
//   1. Initiator: CreateMessageInitiation  → buffer_1
//   2. Responder: ConsumeMessageInitiation(buffer_1)
//   3. Responder: CreateMessageResponse    → buffer_2
//   4. Initiator: ConsumeMessageResponse(buffer_2)
//   5. Both:      DeriveSessionKeys
// ============================================================================

struct SimulationResult {
    bool ok{false};
    std::vector<std::uint8_t> initiation_bytes{};
    std::vector<std::uint8_t> response_bytes{};
};

static SimulationResult RunFullSimulation(DskPeerPair& pp, IndexTable& idx) {
    SimulationResult r{};

    // --- Step 1: Initiator sends Type 1 ---
    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return r;
    r.initiation_bytes = *init_bytes;

    // --- Step 2: Responder receives Type 1 ---
    if (!ConsumeMessageInitiation(r.initiation_bytes, pp.responder)) return r;

    // --- Step 3: Responder sends Type 2 ---
    auto resp_bytes = CreateMessageResponse(pp.responder, idx);
    if (!resp_bytes) return r;
    r.response_bytes = *resp_bytes;

    // --- Step 4: Initiator receives Type 2 ---
    if (!ConsumeMessageResponse(r.response_bytes, pp.initiator, idx)) return r;

    // --- Step 5: Both sides derive session keys ---
    if (!DeriveSessionKeys(pp.initiator, idx, true))  return r;
    if (!DeriveSessionKeys(pp.responder, idx, false)) return r;

    r.ok = true;
    return r;
}

// ============================================================================
// DeriveSessionKeys tests  (DG-250)
// ============================================================================

// Full simulation must complete without error
bool DeriveSessionKeys_Succeeds() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    const auto r = RunFullSimulation(pp, idx);
    return test_helper("1", std::to_string(r.ok));
}

// Ticket: "Initiator: send_key = T0, receive_key = T1" — keypair must be installed in Current
bool DeriveSessionKeys_Initiator_KeypairInCurrent() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    return test_helper("1", std::to_string(pp.initiator.keypairs.Current() != nullptr));
}

// Ticket: "Responder: keypairs.next = new_keypair"
bool DeriveSessionKeys_Responder_KeypairInNext() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    return test_helper("1", std::to_string(pp.responder.keypairs.Next() != nullptr));
}

// Ticket: key swap — initiator send_key must equal responder receive_key
bool DeriveSessionKeys_InitiatorSendEqualsResponderReceive() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* i_kp = pp.initiator.keypairs.Current();
    const Keypair* r_kp = pp.responder.keypairs.Next();
    if (!i_kp || !r_kp) return false;

    const bool match = (i_kp->send_key == r_kp->receive_key);
    return test_helper("1", std::to_string(match));
}

// Ticket: key swap — initiator receive_key must equal responder send_key
bool DeriveSessionKeys_InitiatorReceiveEqualsResponderSend() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* i_kp = pp.initiator.keypairs.Current();
    const Keypair* r_kp = pp.responder.keypairs.Next();
    if (!i_kp || !r_kp) return false;

    const bool match = (i_kp->receive_key == r_kp->send_key);
    return test_helper("1", std::to_string(match));
}

// Keys must be non-zero (derivation actually ran)
bool DeriveSessionKeys_KeysAreNonZero() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* kp = pp.initiator.keypairs.Current();
    if (!kp) return false;

    const bool send_nonzero = std::any_of(kp->send_key.begin(), kp->send_key.end(),
                                          [](std::uint8_t b) { return b != 0; });
    const bool recv_nonzero = std::any_of(kp->receive_key.begin(), kp->receive_key.end(),
                                          [](std::uint8_t b) { return b != 0; });
    return test_helper("1", std::to_string(send_nonzero && recv_nonzero));
}

// Ticket: is_initiator flag must be set correctly in the keypair
bool DeriveSessionKeys_IsInitiatorFlag() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* i_kp = pp.initiator.keypairs.Current();
    const Keypair* r_kp = pp.responder.keypairs.Next();
    if (!i_kp || !r_kp) return false;

    return test_helper("1", std::to_string(i_kp->is_initiator && !r_kp->is_initiator));
}

// Ticket: local/remote indices must be set and cross-match between sides
bool DeriveSessionKeys_IndicesCrossMatch() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* i_kp = pp.initiator.keypairs.Current();
    const Keypair* r_kp = pp.responder.keypairs.Next();
    if (!i_kp || !r_kp) return false;

    // Initiator local == Responder remote, and vice versa
    const bool cross = (i_kp->local_index  == r_kp->remote_index) &&
                       (i_kp->remote_index == r_kp->local_index);
    return test_helper("1", std::to_string(cross));
}

// Ticket: IndexTable entry for local_index must now point to the keypair (not handshake)
bool DeriveSessionKeys_IndexTableSwappedToKeypair() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const Keypair* kp = pp.initiator.keypairs.Current();
    if (!kp) return false;

    const auto entry = idx.Lookup(kp->local_index);
    if (!entry) return false;

    // After SwapHandshakeToKeypair: handshake ptr is null, keypair ptr is set
    const bool swapped = (entry->handshake == nullptr && entry->keypair == kp);
    return test_helper("1", std::to_string(swapped));
}

// Ticket: "set the handshake state back to Zeroed"
bool DeriveSessionKeys_HandshakeStateZeroed() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const bool i_zeroed = pp.initiator.handshake.state == HandshakeStateEnum::Zeroed;
    const bool r_zeroed = pp.responder.handshake.state == HandshakeStateEnum::Zeroed;
    return test_helper("1", std::to_string(i_zeroed && r_zeroed));
}

// Ticket: "zero chaining_key" — must be all zeros after DeriveSessionKeys
bool DeriveSessionKeys_ChainingKeyZeroed() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const bool i_zero = pp.initiator.handshake.chaining_key == Blake3Hash{};
    const bool r_zero = pp.responder.handshake.chaining_key == Blake3Hash{};
    return test_helper("1", std::to_string(i_zero && r_zero));
}

// Ticket: "zero hash"
bool DeriveSessionKeys_HashZeroed() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunFullSimulation(pp, idx).ok) return false;

    const bool i_zero = pp.initiator.handshake.hash == Blake3Hash{};
    const bool r_zero = pp.responder.handshake.hash == Blake3Hash{};
    return test_helper("1", std::to_string(i_zero && r_zero));
}

// Wrong state must be rejected — calling on initiator in Zeroed state
bool DeriveSessionKeys_WrongState_Rejected() {
    DskPeerPair pp{};
    if (!SetupDskPeerPair(pp)) return false;
    IndexTable idx;

    // Initiator has not completed a handshake
    const bool rejected = !DeriveSessionKeys(pp.initiator, idx, true);
    return test_helper("1", std::to_string(rejected));
}

// Two independent handshakes must produce different session keys
bool DeriveSessionKeys_KeysAreUnique() {
    DskPeerPair pp1{}, pp2{};
    if (!SetupDskPeerPair(pp1) || !SetupDskPeerPair(pp2)) return false;
    IndexTable idx1, idx2;

    if (!RunFullSimulation(pp1, idx1).ok) return false;
    if (!RunFullSimulation(pp2, idx2).ok) return false;

    const Keypair* kp1 = pp1.initiator.keypairs.Current();
    const Keypair* kp2 = pp2.initiator.keypairs.Current();
    if (!kp1 || !kp2) return false;

    const bool differ = (kp1->send_key != kp2->send_key);
    return test_helper("1", std::to_string(differ));
}

// ============================================================================
// Concurrency test: 1 server, 5 clients, all handshaking simultaneously
//
// Each client-server pair runs in its own thread. The server side is
// represented by a separate Peer per client (as in a real VPN server).
// All pairs share a single IndexTable, which is the server's shared state.
// ============================================================================

bool DeriveSessionKeys_OneServer_FiveClients_Concurrent() {
    constexpr std::size_t kNumClients = 5;

    // One peer pair per client — server has a separate Peer per client connection
    std::array<DskPeerPair, kNumClients> pairs{};
    IndexTable idx; // shared index table, simulates the server

    for (auto& pp : pairs) {
        if (!SetupDskPeerPair(pp)) return false;
    }

    std::array<bool, kNumClients> results{};
    results.fill(false);

    // Launch one thread per client, each running the full 4-step handshake
    std::array<std::thread, kNumClients> threads;
    for (std::size_t i = 0; i < kNumClients; ++i) {
        threads[i] = std::thread([&pairs, &idx, &results, i]() {
            results[i] = RunFullSimulation(pairs[i], idx).ok;
        });
    }

    for (auto& t : threads) t.join();

    // All handshakes must succeed
    for (std::size_t i = 0; i < kNumClients; ++i) {
        if (!results[i]) return test_helper("1", "0");
    }

    // Every initiator must have a Current keypair with non-zero keys
    for (std::size_t i = 0; i < kNumClients; ++i) {
        const Keypair* kp = pairs[i].initiator.keypairs.Current();
        if (!kp) return test_helper("1", "0");
        const bool nonzero = std::any_of(kp->send_key.begin(), kp->send_key.end(),
                                         [](std::uint8_t b) { return b != 0; });
        if (!nonzero) return test_helper("1", "0");
    }

    // Every responder must have a Next keypair
    for (std::size_t i = 0; i < kNumClients; ++i) {
        if (!pairs[i].responder.keypairs.Next()) return test_helper("1", "0");
    }

    // Key symmetry: each pair's initiator.send == responder.receive
    for (std::size_t i = 0; i < kNumClients; ++i) {
        const Keypair* i_kp = pairs[i].initiator.keypairs.Current();
        const Keypair* r_kp = pairs[i].responder.keypairs.Next();
        if (!i_kp || !r_kp) return test_helper("1", "0");
        if (i_kp->send_key    != r_kp->receive_key) return test_helper("1", "0");
        if (i_kp->receive_key != r_kp->send_key)    return test_helper("1", "0");
    }

    // All 5 session keys must be distinct from one another
    for (std::size_t i = 0; i < kNumClients; ++i) {
        for (std::size_t j = i + 1; j < kNumClients; ++j) {
            const Keypair* a = pairs[i].initiator.keypairs.Current();
            const Keypair* b = pairs[j].initiator.keypairs.Current();
            if (!a || !b) return test_helper("1", "0");
            if (a->send_key == b->send_key) return test_helper("1", "0");
        }
    }

    return test_helper("1", "1");
}

#endif // _PQVPN_TESTS_DERIVE_SESSION_KEYS_TESTS_HPP_
