#ifndef _PQVPN_TESTS_HANDSHAKE_INITIATION_TESTS_HPP_
#define _PQVPN_TESTS_HANDSHAKE_INITIATION_TESTS_HPP_

#include "test_utils.hpp"
#include "handshake_processor.hpp"
#include "handshake_messages.hpp"
#include "handshake_constants.hpp"
#include "peer.hpp"
#include "index_table.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <algorithm>
#include <cstdint>

using namespace core::handshake;

// ============================================================================
// Test peer setup
// ============================================================================
// Populates the fields that CreateMessageInitiation reads from the peer:
//   local_static_x25519_public, local_static_mlkem_ek,
//   remote_static_x25519, remote_static_mlkem_ek, precomputed_static_static
// Does NOT populate local private keys or ML-KEM DK — those are not needed
// for initiation creation.
static bool SetupInitiatorPeer(Peer& peer) {
    auto local_kp = core::cryptography::x25519::GenerateKeyPair();
    if (!local_kp) return false;
    peer.local_static_x25519_private = local_kp->private_key;
    peer.local_static_x25519_public  = local_kp->public_key;

    auto local_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!local_mlkem) return false;
    std::copy(local_mlkem->public_key.begin(), local_mlkem->public_key.end(),
              peer.local_static_mlkem_ek.begin());

    auto remote_kp = core::cryptography::x25519::GenerateKeyPair();
    if (!remote_kp) return false;
    peer.remote_static_x25519 = remote_kp->public_key;

    auto remote_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!remote_mlkem) return false;
    std::copy(remote_mlkem->public_key.begin(), remote_mlkem->public_key.end(),
              peer.remote_static_mlkem_ek.begin());

    auto ss = core::cryptography::x25519::DeriveSharedSecret(
        local_kp->private_key, remote_kp->public_key);
    if (!ss) return false;
    peer.precomputed_static_static = *ss;

    return true;
}

// ============================================================================
// CreateMessageInitiation tests
// Based on ticket DG-239 specification, not on implementation details.
// ============================================================================

// Ticket: "produces a serialized handshake initiation message"
bool CreateInitiation_ReturnsMessage() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    return test_helper("1", std::to_string(result.has_value()));
}

// Ticket: total message size is ~3620 bytes (layout specified)
bool CreateInitiation_MessageSize() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;
    return test_helper(std::to_string(kInitiationSize), std::to_string(result->size()));
}

// Ticket step 13: "Type (4 bytes LE, value 1)"
bool CreateInitiation_TypeField() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result || result->size() < 4) return false;

    const auto& buf = *result;
    const std::uint32_t type = static_cast<std::uint32_t>(buf[0])
                             | (static_cast<std::uint32_t>(buf[1]) << 8)
                             | (static_cast<std::uint32_t>(buf[2]) << 16)
                             | (static_cast<std::uint32_t>(buf[3]) << 24);
    return test_helper("1", std::to_string(type));
}

// Ticket step 13: "Sender Index (4 bytes LE)" must match the assigned index
bool CreateInitiation_SenderIndexMatchesState() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result || result->size() < 8) return false;

    const auto& buf = *result;
    const std::uint32_t msg_index = static_cast<std::uint32_t>(buf[4])
                                  | (static_cast<std::uint32_t>(buf[5]) << 8)
                                  | (static_cast<std::uint32_t>(buf[6]) << 16)
                                  | (static_cast<std::uint32_t>(buf[7]) << 24);
    return test_helper(std::to_string(peer.handshake.local_index), std::to_string(msg_index));
}

// Ticket step 14: "Set state to InitiationCreated"
bool CreateInitiation_StateIsInitiationCreated() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const bool correct = peer.handshake.state == HandshakeStateEnum::InitiationCreated;
    return test_helper("1", std::to_string(correct));
}

// Ticket step 14: "Store C ... in the HandshakeState struct"
// C must differ from its initial value because the handshake has absorbed keys
bool CreateInitiation_ChainingKeyModified() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const bool modified = peer.handshake.chaining_key != InitialChainingKey();
    return test_helper("1", std::to_string(modified));
}

// Ticket step 14: "Store ... H ... in the HandshakeState struct"
// H must differ because all wire fields have been mixed in
bool CreateInitiation_HashModified() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const bool modified = peer.handshake.hash != InitialHash();
    return test_helper("1", std::to_string(modified));
}

// Ticket step 14: "Store ... e_priv ... in the HandshakeState struct"
// "Do NOT zero the ephemeral private keys yet"
bool CreateInitiation_EphemeralX25519PrivateStored() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const auto& priv = peer.handshake.local_ephemeral_x25519_private;
    const bool non_zero = std::any_of(priv.begin(), priv.end(),
                                      [](std::uint8_t b) { return b != 0; });
    return test_helper("1", std::to_string(non_zero));
}

// Ticket step 14: "Store ... dk_ephemeral ... in the HandshakeState struct"
// "Do NOT zero the ephemeral private keys yet"
bool CreateInitiation_EphemeralMlKemDkStored() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const auto& dk = peer.handshake.local_ephemeral_mlkem_dk;
    const bool non_zero = std::any_of(dk.begin(), dk.end(),
                                      [](std::uint8_t b) { return b != 0; });
    return test_helper("1", std::to_string(non_zero));
}

// Ticket layout: "X25519 Ephemeral Pub: 32 bytes" at offset 8
// Must match the public key stored in handshake state
bool CreateInitiation_EphemeralX25519InMessageMatchesState() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result || result->size() < 40) return false;

    const bool match = std::equal(
        result->begin() + 8, result->begin() + 40,
        peer.handshake.local_ephemeral_x25519_public.begin());
    return test_helper("1", std::to_string(match));
}

// Ticket layout: "ML-KEM Ephemeral EK: 1184 bytes" at offset 40
// Must match the ephemeral EK stored in handshake state
bool CreateInitiation_EphemeralMlKemEkInMessageMatchesState() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result || result->size() < 1224) return false;

    const bool match = std::equal(
        result->begin() + 40, result->begin() + 1224,
        peer.handshake.local_ephemeral_mlkem_ek.begin());
    return test_helper("1", std::to_string(match));
}

// Ticket step 15: "MAC fields ... appended by the cookie/MAC system AFTER this
// function returns. Leave 32 bytes of space at the end of the message for them."
bool CreateInitiation_MacFieldsAreZero() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result || result->size() != kInitiationSize) return false;

    // mac1: [3588..3603], mac2: [3604..3619]
    const bool all_zero = std::all_of(result->begin() + 3588, result->end(),
                                      [](std::uint8_t b) { return b == 0; });
    return test_helper("1", std::to_string(all_zero));
}

// Ticket step 12: "Call IndexTable::NewIndex(peer, handshake) to get a random
// uint32 and register this handshake in the global index table"
bool CreateInitiation_IndexTableEntryExists() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const auto entry = index_table.Lookup(peer.handshake.local_index);
    return test_helper("1", std::to_string(entry.has_value()));
}

// IndexTable entry must associate the index with the correct peer
bool CreateInitiation_IndexTableEntryPointsToPeer() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const auto entry = index_table.Lookup(peer.handshake.local_index);
    if (!entry) return false;
    return test_helper("1", std::to_string(entry->peer == &peer));
}

// Ticket step 12: assigned index must be non-zero
// (IndexTable::NewIndex loops until a non-zero index is found)
bool CreateInitiation_LocalIndexNonZero() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    return test_helper("1", std::to_string(peer.handshake.local_index != 0));
}

// Ticket step 3: "Generate a fresh X25519 keypair" — keys must differ between
// independent calls (ephemeral randomness)
bool CreateInitiation_EphemeralKeysAreRandom() {
    Peer peer1{};
    Peer peer2{};
    if (!SetupInitiatorPeer(peer1) || !SetupInitiatorPeer(peer2)) return false;
    IndexTable index_table;

    auto result1 = CreateMessageInitiation(peer1, index_table);
    auto result2 = CreateMessageInitiation(peer2, index_table);
    if (!result1 || !result2 || result1->size() < 40 || result2->size() < 40) return false;

    // Compare X25519 ephemeral public keys at offset [8..39]
    const bool differ = !std::equal(
        result1->begin() + 8, result1->begin() + 40,
        result2->begin() + 8);
    return test_helper("1", std::to_string(differ));
}

// Message must round-trip through DeserializeInitiation without error
bool CreateInitiation_MessageDeserializes() {
    Peer peer{};
    if (!SetupInitiatorPeer(peer)) return false;
    IndexTable index_table;

    auto result = CreateMessageInitiation(peer, index_table);
    if (!result) return false;

    const auto msg = DeserializeInitiation(result->data(), result->size());
    return test_helper("1", std::to_string(msg.has_value()));
}

#endif // _PQVPN_TESTS_HANDSHAKE_INITIATION_TESTS_HPP_
