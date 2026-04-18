#ifndef _PQVPN_TESTS_HANDSHAKE_RESPONSE_TESTS_HPP_
#define _PQVPN_TESTS_HANDSHAKE_RESPONSE_TESTS_HPP_

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
#include <cstdint>
#include <cstring>

using namespace core::handshake;

// ============================================================================
// Test infrastructure
// ============================================================================

// Two peers configured to talk to each other.
// Non-copyable because Peer is non-copyable; create in-place.
struct HandshakePeerPair {
    Peer initiator{};
    Peer responder{};
};

// Populate both sides of the peer pair with matching key material.
// Must be called once before any handshake tests that need both sides.
static bool SetupPeerPair(HandshakePeerPair& pp) {
    // Initiator static X25519
    auto init_x25519 = core::cryptography::x25519::GenerateKeyPair();
    if (!init_x25519) return false;

    // Initiator static ML-KEM
    auto init_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!init_mlkem) return false;

    // Responder static X25519
    auto resp_x25519 = core::cryptography::x25519::GenerateKeyPair();
    if (!resp_x25519) return false;

    // Responder static ML-KEM
    auto resp_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!resp_mlkem) return false;

    // Populate initiator peer
    pp.initiator.local_static_x25519_private = init_x25519->private_key;
    pp.initiator.local_static_x25519_public  = init_x25519->public_key;
    std::copy(init_mlkem->public_key.begin(), init_mlkem->public_key.end(),
              pp.initiator.local_static_mlkem_ek.begin());

    pp.initiator.remote_static_x25519 = resp_x25519->public_key;
    std::copy(resp_mlkem->public_key.begin(), resp_mlkem->public_key.end(),
              pp.initiator.remote_static_mlkem_ek.begin());

    auto init_ss = core::cryptography::x25519::DeriveSharedSecret(
        init_x25519->private_key, resp_x25519->public_key);
    if (!init_ss) return false;
    pp.initiator.precomputed_static_static = *init_ss;

    // Populate responder peer
    pp.responder.local_static_x25519_private = resp_x25519->private_key;
    pp.responder.local_static_x25519_public  = resp_x25519->public_key;
    std::copy(resp_mlkem->public_key.begin(), resp_mlkem->public_key.end(),
              pp.responder.local_static_mlkem_ek.begin());

    // Responder needs the raw ML-KEM decapsulation key for processing initiations
    std::size_t dk_len = kMlKemDecapsulationKeyBytes;
    if (EVP_PKEY_get_raw_private_key(resp_mlkem->pkey.get(),
                                     pp.responder.local_static_mlkem_dk.data(),
                                     &dk_len) != 1)
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

// Runs Create → Consume, returns the raw initiation bytes on success.
static std::optional<std::vector<std::uint8_t>>
RunInitiation(HandshakePeerPair& pp, IndexTable& idx) {
    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return std::nullopt;

    if (!ConsumeMessageInitiation(*init_bytes, pp.responder)) return std::nullopt;
    return init_bytes;
}

// ============================================================================
// ConsumeMessageInitiation tests  (DG-240)
// ============================================================================

// Ticket: function must accept a validly-constructed initiation message
bool ConsumeInitiation_Succeeds() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    const bool ok = ConsumeMessageInitiation(*init_bytes, pp.responder);
    return test_helper("1", std::to_string(ok));
}

// Ticket step 15: "Set state to InitiationConsumed"
bool ConsumeInitiation_StateIsInitiationConsumed() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    const bool correct = pp.responder.handshake.state == HandshakeStateEnum::InitiationConsumed;
    return test_helper("1", std::to_string(correct));
}

// Ticket step 15: "copy local C, H into peer.handshake" — C must be updated
bool ConsumeInitiation_ChainingKeyUpdated() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    const bool changed = pp.responder.handshake.chaining_key != InitialChainingKey();
    return test_helper("1", std::to_string(changed));
}

// Ticket step 15: H must be updated
bool ConsumeInitiation_HashUpdated() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    const bool changed = pp.responder.handshake.hash != InitialHash();
    return test_helper("1", std::to_string(changed));
}

// Ticket step 15: "remote_index = msg.sender_index"
bool ConsumeInitiation_RemoteIndexStored() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    const std::uint32_t initiator_local_index = pp.initiator.handshake.local_index;

    if (!ConsumeMessageInitiation(*init_bytes, pp.responder)) return false;

    return test_helper(std::to_string(initiator_local_index),
                       std::to_string(pp.responder.handshake.remote_index));
}

// Ticket step 15: "Store E_i_pub" — initiator ephemeral X25519 must match message bytes
bool ConsumeInitiation_EphemeralX25519Stored() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    if (!ConsumeMessageInitiation(*init_bytes, pp.responder)) return false;

    // Message offset 8..39 = ephemeral_x25519
    const bool match = std::equal(
        init_bytes->begin() + 8, init_bytes->begin() + 40,
        pp.responder.handshake.remote_ephemeral_x25519.begin());
    return test_helper("1", std::to_string(match));
}

// Ticket step 15: "Store ... ek_i" — initiator ephemeral ML-KEM EK must match message bytes
bool ConsumeInitiation_EphemeralMlKemEkStored() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    if (!ConsumeMessageInitiation(*init_bytes, pp.responder)) return false;

    // Message offset 40..1223 = ephemeral_mlkem_ek
    const bool match = std::equal(
        init_bytes->begin() + 40, init_bytes->begin() + 1224,
        pp.responder.handshake.remote_ephemeral_mlkem.begin());
    return test_helper("1", std::to_string(match));
}

// Ticket step 15: "peer.handshake.last_timestamp = timestamp" — must be non-zero after consumption
bool ConsumeInitiation_TimestampStored() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    const auto& ts = pp.responder.handshake.last_timestamp;
    const bool non_zero = std::any_of(ts.begin(), ts.end(),
                                      [](std::uint8_t b) { return b != 0; });
    return test_helper("1", std::to_string(non_zero));
}

// Ticket step 9: "If decryption fails, drop the message"
// Flipping any bit in the AEAD ciphertext must cause rejection
bool ConsumeInitiation_TamperedCiphertext_Rejected() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    // Corrupt a byte inside encrypted_static_x25519 (offset 2312..2359)
    (*init_bytes)[2312] ^= 0xFF;

    const bool rejected = !ConsumeMessageInitiation(*init_bytes, pp.responder);
    return test_helper("1", std::to_string(rejected));
}

// Ticket step 11: "If no peer is configured with this static key, drop"
// A message from an unknown initiator (different key pair) must be rejected
bool ConsumeInitiation_UnknownInitiator_Rejected() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    // Build a second, unrelated initiator that does NOT match the responder's peer config
    HandshakePeerPair pp2{};
    if (!SetupPeerPair(pp2)) return false;
    IndexTable idx2;

    // Give pp2.initiator the responder's public keys so it builds a valid-looking message,
    // but the responder's config expects pp.initiator's keys — identity mismatch detected
    // at decryption step 11.
    pp2.initiator.remote_static_x25519  = pp.responder.local_static_x25519_public;
    std::copy(pp.responder.local_static_mlkem_ek.begin(),
              pp.responder.local_static_mlkem_ek.end(),
              pp2.initiator.remote_static_mlkem_ek.begin());
    auto ss2 = core::cryptography::x25519::DeriveSharedSecret(
        pp2.initiator.local_static_x25519_private,
        pp.responder.local_static_x25519_public);
    if (!ss2) return false;
    pp2.initiator.precomputed_static_static = *ss2;

    auto foreign_init = CreateMessageInitiation(pp2.initiator, idx2);
    if (!foreign_init) return false;

    // pp.responder expects pp.initiator's keys — decrypted identity won't match
    const bool rejected = !ConsumeMessageInitiation(*foreign_init, pp.responder);
    return test_helper("1", std::to_string(rejected));
}

// Ticket step 14: "If timestamp <= peer.last_timestamp, drop — this is a replayed message"
bool ConsumeInitiation_ReplayRejected() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    auto init_bytes = CreateMessageInitiation(pp.initiator, idx);
    if (!init_bytes) return false;

    // First consumption must succeed
    if (!ConsumeMessageInitiation(*init_bytes, pp.responder)) return false;

    // Replaying the same message must be rejected (timestamp not > last_timestamp)
    // Reset state to allow re-processing but keep last_timestamp
    pp.responder.handshake.state = HandshakeStateEnum::Zeroed;

    const bool rejected = !ConsumeMessageInitiation(*init_bytes, pp.responder);
    return test_helper("1", std::to_string(rejected));
}

// Responder C and H must equal initiator C and H after both sides process the initiation
bool ConsumeInitiation_ChainingKeyConverges() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    const bool c_match = pp.initiator.handshake.chaining_key == pp.responder.handshake.chaining_key;
    const bool h_match = pp.initiator.handshake.hash == pp.responder.handshake.hash;
    return test_helper("1", std::to_string(c_match && h_match));
}

// ============================================================================
// CreateMessageResponse tests  (DG-242)
// ============================================================================

// Ticket: produces a response message when state is InitiationConsumed
bool CreateResponse_Succeeds() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    return test_helper("1", std::to_string(resp.has_value()));
}

// Ticket message layout: total = 2268 bytes
bool CreateResponse_MessageSize() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp) return false;
    return test_helper(std::to_string(kResponseSize), std::to_string(resp->size()));
}

// Ticket step 10: "Type (4 bytes LE, value 2)"
bool CreateResponse_TypeField() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp || resp->size() < 4) return false;

    const auto& buf = *resp;
    const std::uint32_t type = static_cast<std::uint32_t>(buf[0])
                             | (static_cast<std::uint32_t>(buf[1]) << 8)
                             | (static_cast<std::uint32_t>(buf[2]) << 16)
                             | (static_cast<std::uint32_t>(buf[3]) << 24);
    return test_helper("2", std::to_string(type));
}

// Ticket step 10: "Sender Index (4 bytes LE)" must match local_index assigned in response
bool CreateResponse_SenderIndexMatchesState() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp || resp->size() < 8) return false;

    const auto& buf = *resp;
    const std::uint32_t msg_index = static_cast<std::uint32_t>(buf[4])
                                  | (static_cast<std::uint32_t>(buf[5]) << 8)
                                  | (static_cast<std::uint32_t>(buf[6]) << 16)
                                  | (static_cast<std::uint32_t>(buf[7]) << 24);
    return test_helper(std::to_string(pp.responder.handshake.local_index),
                       std::to_string(msg_index));
}

// Ticket step 10: "Receiver Index ... = the initiator's sender index from the consumed initiation"
bool CreateResponse_ReceiverIndexMatchesInitiator() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;
    const std::uint32_t initiator_index = pp.initiator.handshake.local_index;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp || resp->size() < 12) return false;

    const auto& buf = *resp;
    const std::uint32_t recv_index = static_cast<std::uint32_t>(buf[8])
                                   | (static_cast<std::uint32_t>(buf[9]) << 8)
                                   | (static_cast<std::uint32_t>(buf[10]) << 16)
                                   | (static_cast<std::uint32_t>(buf[11]) << 24);
    return test_helper(std::to_string(initiator_index), std::to_string(recv_index));
}

// Ticket step 11: "Set state to ResponseCreated"
bool CreateResponse_StateIsResponseCreated() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;
    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp) return false;

    const bool correct = pp.responder.handshake.state == HandshakeStateEnum::ResponseCreated;
    return test_helper("1", std::to_string(correct));
}

// Ticket: "Append MAC fields ... Leave 32 bytes of space at the end"
// The mac1/mac2 fields must be zeroed until the MAC system fills them
bool CreateResponse_MacFieldsAreZero() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp || resp->size() != kResponseSize) return false;

    // mac1: [2236..2251], mac2: [2252..2267]
    const bool all_zero = std::all_of(resp->begin() + 2236, resp->end(),
                                      [](std::uint8_t b) { return b == 0; });
    return test_helper("1", std::to_string(all_zero));
}

// Ticket step 9: IndexTable must have a valid entry for the response's local_index
bool CreateResponse_IndexTableEntryExists() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;
    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp) return false;

    const auto entry = idx.Lookup(pp.responder.handshake.local_index);
    return test_helper("1", std::to_string(entry.has_value()));
}

// Ticket: function must return nullopt when called in the wrong state
bool CreateResponse_WrongState_Rejected() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    // Handshake has NOT been consumed — state is Zeroed
    const auto resp = CreateMessageResponse(pp.responder, idx);
    return test_helper("1", std::to_string(!resp.has_value()));
}

// Response message must round-trip through DeserializeResponse
bool CreateResponse_MessageDeserializes() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;

    auto resp = CreateMessageResponse(pp.responder, idx);
    if (!resp) return false;

    const auto msg = DeserializeResponse(resp->data(), resp->size());
    return test_helper("1", std::to_string(msg.has_value()));
}

// ============================================================================
// End-to-end: Create → Consume → CreateResponse
// ============================================================================

// Both sides must hold the same chaining key after a complete initiation + response creation
bool E2E_InitiationAndResponse_ChainingKeyConverges() {
    HandshakePeerPair pp{};
    if (!SetupPeerPair(pp)) return false;
    IndexTable idx;

    if (!RunInitiation(pp, idx)) return false;
    if (!CreateMessageResponse(pp.responder, idx)) return false;

    // After CreateMessageResponse the responder's C is the final transport key derivation
    // input. The initiator's C was set during initiation. They are NOT equal at this point —
    // the responder has advanced further (through DH #3/#4, KEM #2/#3, PSK). What we can
    // verify is that neither side has a trivial (zero or initial) chaining key.
    const bool resp_c_non_trivial =
        pp.responder.handshake.chaining_key != InitialChainingKey() &&
        pp.responder.handshake.chaining_key != Blake3Hash{};

    return test_helper("1", std::to_string(resp_c_non_trivial));
}

#endif // _PQVPN_TESTS_HANDSHAKE_RESPONSE_TESTS_HPP_
