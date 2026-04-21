#include "handshake_processor.hpp"
#include "handshake_helpers.hpp"
#include "handshake_messages.hpp"
#include "handshake_constants.hpp"
#include "handshake_state.hpp"
#include "secure_memory.hpp"
#include "tai64n.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <mutex>

namespace core::handshake {

using core::utils::secure_zero;
using core::utils::ct_memcmp;

// Reconstructs an EVP_PKEY for ML-KEM-768 from 2400 raw decapsulation-key bytes.
static core::cryptography::ml_kem::EvpPkeyPtr
RebuildMlKemKey(const std::array<std::uint8_t, kMlKemDecapsulationKeyBytes>& dk) {
    EVP_PKEY* p = EVP_PKEY_new_raw_private_key_ex(
        nullptr, "ML-KEM-768", nullptr, dk.data(), dk.size());
    return core::cryptography::ml_kem::EvpPkeyPtr{p};
}

// ============================================================================
// CreateMessageInitiation  (DG-239)
// ============================================================================

std::optional<std::vector<std::uint8_t>>
CreateMessageInitiation(Peer& peer, IndexTable& index_table) {
    // Step 1: Initialize state
    Blake3Hash C = InitialChainingKey();
    Blake3Hash H = InitialHash();

    // Step 2: Mix responder static keys into transcript
    MixHash(H, peer.remote_static_x25519);
    MixHash(H, peer.remote_static_mlkem_ek);

    // Step 3: Generate ephemeral keypairs
    auto e_x25519 = core::cryptography::x25519::GenerateKeyPair();
    if (!e_x25519) return std::nullopt;

    auto e_mlkem = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!e_mlkem) return std::nullopt;

    // Extract ML-KEM decapsulation key as raw bytes for storage in handshake state
    std::array<std::uint8_t, kMlKemDecapsulationKeyBytes> dk_ephemeral{};
    std::size_t dk_len = kMlKemDecapsulationKeyBytes;
    if (EVP_PKEY_get_raw_private_key(e_mlkem->pkey.get(), dk_ephemeral.data(), &dk_len) != 1
        || dk_len != kMlKemDecapsulationKeyBytes) {
        return std::nullopt;
    }

    // Step 4: Mix X25519 ephemeral public key
    if (!MixKey(C, e_x25519->public_key)) return std::nullopt;
    MixHash(H, e_x25519->public_key);

    // Step 5: Mix ML-KEM ephemeral encapsulation key
    ConstByteSpan ek_span{e_mlkem->public_key.data(), e_mlkem->public_key.size()};
    if (!MixKey(C, ek_span)) return std::nullopt;
    MixHash(H, ek_span);

    // Step 6: X25519 DH #1 (ephemeral-static)
    auto dh_es_opt = core::cryptography::x25519::DeriveSharedSecret(
        e_x25519->private_key, peer.remote_static_x25519);
    if (!dh_es_opt) return std::nullopt;
    auto dh_es = *dh_es_opt;

    auto kdf2_1 = KDF2(C, dh_es);
    secure_zero(dh_es);
    if (!kdf2_1) return std::nullopt;
    C = std::get<0>(*kdf2_1);
    Blake3Hash enc_key1 = std::get<1>(*kdf2_1);
    secure_zero(std::get<1>(*kdf2_1));

    // Step 7: ML-KEM KEM #1 (encapsulate to responder static key)
    auto encaps_es = core::cryptography::ml_kem::Encapsulate(
        peer.remote_static_mlkem_ek,
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!encaps_es) {
        secure_zero(enc_key1);
        return std::nullopt;
    }

    ConstByteSpan ss_span{encaps_es->shared_secret.data(), encaps_es->shared_secret.size()};
    if (!MixKey(C, ss_span)) {
        secure_zero(enc_key1);
        secure_zero(encaps_es->shared_secret.data(), encaps_es->shared_secret.size());
        return std::nullopt;
    }
    secure_zero(encaps_es->shared_secret.data(), encaps_es->shared_secret.size());
    MixHash(H, ConstByteSpan{encaps_es->ciphertext.data(), encaps_es->ciphertext.size()});

    // Step 8: Encrypt initiator static X25519 key
    auto enc_static_x25519 = EncryptAndHash(H, enc_key1, peer.local_static_x25519_public);
    secure_zero(enc_key1);
    if (!enc_static_x25519 || enc_static_x25519->size() != 48) return std::nullopt;

    // Step 9: Encrypt initiator static ML-KEM EK (derive new encryption key from empty input)
    auto kdf2_2 = KDF2(C, ConstByteSpan{});
    if (!kdf2_2) return std::nullopt;
    C = std::get<0>(*kdf2_2);
    Blake3Hash enc_key2 = std::get<1>(*kdf2_2);
    secure_zero(std::get<1>(*kdf2_2));

    auto enc_static_mlkem = EncryptAndHash(H, enc_key2, peer.local_static_mlkem_ek);
    secure_zero(enc_key2);
    if (!enc_static_mlkem || enc_static_mlkem->size() != 1200) return std::nullopt;

    // Step 10: X25519 DH #2 (static-static, precomputed)
    auto kdf2_3 = KDF2(C, peer.precomputed_static_static);
    if (!kdf2_3) return std::nullopt;
    C = std::get<0>(*kdf2_3);
    Blake3Hash enc_key3 = std::get<1>(*kdf2_3);
    secure_zero(std::get<1>(*kdf2_3));

    // Step 11: Encrypt TAI64N timestamp
    static core::utils::Tai64n tai64n_gen{};
    auto ts = tai64n_gen.Now().Data();
    auto enc_timestamp = EncryptAndHash(H, enc_key3, ts);
    secure_zero(enc_key3);
    if (!enc_timestamp || enc_timestamp->size() != 28) return std::nullopt;

    // Step 12: Assign sender index
    const std::uint32_t local_index = index_table.NewIndex(&peer, &peer.handshake);

    // Step 13: Build initiation message
    InitiationMsg msg{};
    msg.sender_index = local_index;
    std::copy(e_x25519->public_key.begin(), e_x25519->public_key.end(),
              msg.ephemeral_x25519.begin());
    std::copy(e_mlkem->public_key.begin(), e_mlkem->public_key.end(),
              msg.ephemeral_mlkem_ek.begin());
    std::copy(encaps_es->ciphertext.begin(), encaps_es->ciphertext.end(),
              msg.kem_ciphertext_es.begin());
    std::copy(enc_static_x25519->begin(), enc_static_x25519->end(),
              msg.encrypted_static_x25519.begin());
    std::copy(enc_static_mlkem->begin(), enc_static_mlkem->end(),
              msg.encrypted_static_mlkem.begin());
    std::copy(enc_timestamp->begin(), enc_timestamp->end(),
              msg.encrypted_timestamp.begin());
    // mac1/mac2 are zero — filled by MAC system (DG-244) before sending

    // Step 14: Commit handshake state
    // Ephemeral private keys are NOT zeroed — needed to process the response
    {
        std::lock_guard lock(peer.handshake.mutex);
        peer.handshake.chaining_key = C;
        peer.handshake.hash         = H;
        peer.handshake.local_ephemeral_x25519_private = e_x25519->private_key;
        peer.handshake.local_ephemeral_x25519_public  = e_x25519->public_key;
        peer.handshake.local_ephemeral_mlkem_dk = dk_ephemeral;
        std::copy(e_mlkem->public_key.begin(), e_mlkem->public_key.end(),
                  peer.handshake.local_ephemeral_mlkem_ek.begin());
        peer.handshake.local_index = local_index;
        peer.handshake.state = HandshakeStateEnum::InitiationCreated;
    }

    secure_zero(dk_ephemeral); // zero the local copy; handshake state holds the canonical copy

    // Step 15: Serialize — mac1/mac2 (last 32 bytes) are zeroed, ready for MAC system
    return SerializeInitiation(msg);
}

// ============================================================================
// ConsumeMessageInitiation  (DG-240)
// ============================================================================

bool ConsumeMessageInitiation(ConstByteSpan msg, Peer& peer) {
    // Step 1: Parse message — drop silently on wrong size or type
    auto initiation = DeserializeInitiation(msg.data(), msg.size());
    if (!initiation) return false;

    // Step 2: Verify mac1 before any expensive crypto
    // TODO: DG-244 — mac1 verification not yet implemented
    // VerifyMac1(peer.mac1_key, ...) goes here

    // Step 3: mac2 check if under load
    // TODO: DG-244 / DG-246 — under-load detection and cookie reply not yet implemented

    // Step 4: Initialize local C and H — do NOT touch peer.handshake yet
    Blake3Hash C = InitialChainingKey();
    Blake3Hash H = InitialHash();
    MixHash(H, peer.local_static_x25519_public);
    MixHash(H, peer.local_static_mlkem_ek);

    // Step 5: Mix X25519 ephemeral
    if (!MixKey(C, initiation->ephemeral_x25519)) return false;
    MixHash(H, initiation->ephemeral_x25519);

    // Step 6: Mix ML-KEM ephemeral EK
    if (!MixKey(C, initiation->ephemeral_mlkem_ek)) return false;
    MixHash(H, initiation->ephemeral_mlkem_ek);

    // Step 7: X25519 DH #1 (es): X25519(own_static_priv, initiator_ephemeral_pub)
    auto dh_es_opt = core::cryptography::x25519::DeriveSharedSecret(
        peer.local_static_x25519_private, initiation->ephemeral_x25519);
    if (!dh_es_opt) return false;
    auto dh_es = *dh_es_opt;

    auto kdf2_1 = KDF2(C, dh_es);
    secure_zero(dh_es);
    if (!kdf2_1) return false;
    C = std::get<0>(*kdf2_1);
    Blake3Hash dec_key1 = std::get<1>(*kdf2_1);
    secure_zero(std::get<1>(*kdf2_1));

    // Step 8: ML-KEM KEM #1 — decapsulate ct_es with own static ML-KEM DK
    auto static_dk = RebuildMlKemKey(peer.local_static_mlkem_dk);
    if (!static_dk) {
        secure_zero(dec_key1);
        return false;
    }
    auto ss_kem_es = core::cryptography::ml_kem::Decapsulate(
        static_dk.get(), initiation->kem_ciphertext_es);
    static_dk.reset();
    if (!ss_kem_es) {
        secure_zero(dec_key1);
        return false;
    }
    if (!MixKey(C, ConstByteSpan{ss_kem_es->data(), ss_kem_es->size()})) {
        secure_zero(dec_key1);
        secure_zero(ss_kem_es->data(), ss_kem_es->size());
        return false;
    }
    secure_zero(ss_kem_es->data(), ss_kem_es->size());
    MixHash(H, initiation->kem_ciphertext_es);

    // Step 9: Decrypt initiator's static X25519 — first real validation gate
    auto dec_static_x25519 = DecryptAndHash(H, dec_key1, initiation->encrypted_static_x25519);
    secure_zero(dec_key1);
    if (!dec_static_x25519 || dec_static_x25519->size() != 32) return false;

    core::cryptography::x25519::PublicKey initiator_static_x25519{};
    std::copy(dec_static_x25519->begin(), dec_static_x25519->end(),
              initiator_static_x25519.begin());

    // Step 10: Decrypt initiator's static ML-KEM EK
    auto kdf2_2 = KDF2(C, ConstByteSpan{});
    if (!kdf2_2) return false;
    C = std::get<0>(*kdf2_2);
    Blake3Hash dec_key2 = std::get<1>(*kdf2_2);
    secure_zero(std::get<1>(*kdf2_2));

    auto dec_static_mlkem = DecryptAndHash(H, dec_key2, initiation->encrypted_static_mlkem);
    secure_zero(dec_key2);
    if (!dec_static_mlkem || dec_static_mlkem->size() != kMlKemEncapsulationKeyBytes)
        return false;

    // Step 11: Identity check.
    // If remote_static_x25519 is all-zeros the server is in open-server mode: accept any
    // authenticated initiator and compute the static-static DH on the fly from the
    // decrypted initiator key.  Otherwise verify against the configured peer key.
    core::cryptography::x25519::SharedSecret ss_static{};
    {
        const bool open_server = std::all_of(
            peer.remote_static_x25519.begin(), peer.remote_static_x25519.end(),
            [](std::uint8_t b){ return b == 0; });

        if (open_server) {
            auto computed = core::cryptography::x25519::DeriveSharedSecret(
                peer.local_static_x25519_private, initiator_static_x25519);
            if (!computed) return false;
            ss_static = *computed;
        } else {
            if (!ct_memcmp(initiator_static_x25519, peer.remote_static_x25519)) return false;
            ss_static = peer.precomputed_static_static;
        }
    }

    // Step 12: X25519 DH #2 (ss)
    auto kdf2_3 = KDF2(C, ss_static);
    secure_zero(ss_static);
    if (!kdf2_3) return false;
    C = std::get<0>(*kdf2_3);
    Blake3Hash dec_key3 = std::get<1>(*kdf2_3);
    secure_zero(std::get<1>(*kdf2_3));

    // Step 13: Decrypt timestamp
    auto dec_ts = DecryptAndHash(H, dec_key3, initiation->encrypted_timestamp);
    secure_zero(dec_key3);
    if (!dec_ts || dec_ts->size() != 12) return false;

    std::array<std::uint8_t, 12> timestamp{};
    std::copy(dec_ts->begin(), dec_ts->end(), timestamp.begin());

    // Step 14: Anti-replay — timestamp must be strictly greater than last seen
    const auto now = std::chrono::system_clock::now();
    {
        std::lock_guard lock(peer.handshake.mutex);

        if (std::memcmp(timestamp.data(), peer.handshake.last_timestamp.data(), 12) <= 0)
            return false;

        // Rate-limit: at most one consumed initiation per kHandshakeInitiationRate (20 ms)
        const auto epoch = std::chrono::system_clock::time_point{};
        if (peer.handshake.last_initiation_consumption != epoch) {
            if (now - peer.handshake.last_initiation_consumption < kHandshakeInitiationRate)
                return false;
        }

        // Step 15: Commit state — all checks passed
        peer.handshake.chaining_key = C;
        peer.handshake.hash         = H;
        peer.handshake.remote_ephemeral_x25519 = initiation->ephemeral_x25519;
        peer.handshake.remote_ephemeral_mlkem  = initiation->ephemeral_mlkem_ek;
        std::copy(dec_static_mlkem->begin(), dec_static_mlkem->end(),
                  peer.handshake.remote_static_mlkem.begin());
        peer.handshake.remote_index             = initiation->sender_index;
        peer.handshake.remote_static_x25519     = initiator_static_x25519;
        peer.handshake.last_timestamp           = timestamp;
        peer.handshake.last_initiation_consumption = now;
        peer.handshake.state = HandshakeStateEnum::InitiationConsumed;
    }

    return true;
}

// ============================================================================
// CreateMessageResponse  (DG-242)
// ============================================================================

std::optional<std::vector<std::uint8_t>>
CreateMessageResponse(Peer& peer, IndexTable& index_table) {
    // Load and verify state under lock, then work with local copies
    Blake3Hash C, H;
    std::array<std::uint8_t, 32>   remote_ephemeral_x25519{};
    std::array<std::uint8_t, 1184> remote_ephemeral_mlkem{};
    std::array<std::uint8_t, 1184> remote_static_mlkem{};
    std::uint32_t remote_index = 0;

    {
        std::lock_guard lock(peer.handshake.mutex);
        if (peer.handshake.state != HandshakeStateEnum::InitiationConsumed)
            return std::nullopt;
        C = peer.handshake.chaining_key;
        H = peer.handshake.hash;
        remote_ephemeral_x25519 = peer.handshake.remote_ephemeral_x25519;
        remote_ephemeral_mlkem  = peer.handshake.remote_ephemeral_mlkem;
        remote_static_mlkem     = peer.handshake.remote_static_mlkem;
        remote_index            = peer.handshake.remote_index;
    }

    // Step 1: Generate responder ephemeral X25519 keypair
    auto e_r = core::cryptography::x25519::GenerateKeyPair();
    if (!e_r) return std::nullopt;

    // Step 2: Mix responder ephemeral into transcript
    if (!MixKey(C, e_r->public_key)) return std::nullopt;
    MixHash(H, e_r->public_key);

    // Step 3: X25519 DH #3 (ee) — responder ephemeral × initiator ephemeral
    auto dh_ee_opt = core::cryptography::x25519::DeriveSharedSecret(
        e_r->private_key, remote_ephemeral_x25519);
    if (!dh_ee_opt) return std::nullopt;
    auto dh_ee = *dh_ee_opt;
    if (!MixKey(C, dh_ee)) {
        secure_zero(dh_ee);
        return std::nullopt;
    }
    secure_zero(dh_ee);

    // Step 4: ML-KEM KEM #2 — encapsulate to initiator's ephemeral ML-KEM key
    auto encaps_ee = core::cryptography::ml_kem::Encapsulate(
        remote_ephemeral_mlkem,
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!encaps_ee) return std::nullopt;
    if (!MixKey(C, ConstByteSpan{encaps_ee->shared_secret.data(), encaps_ee->shared_secret.size()})) {
        secure_zero(encaps_ee->shared_secret.data(), encaps_ee->shared_secret.size());
        return std::nullopt;
    }
    secure_zero(encaps_ee->shared_secret.data(), encaps_ee->shared_secret.size());
    MixHash(H, ConstByteSpan{encaps_ee->ciphertext.data(), encaps_ee->ciphertext.size()});

    // Step 5: X25519 DH #4 (se) — responder ephemeral × initiator static
    auto dh_se_opt = core::cryptography::x25519::DeriveSharedSecret(
        e_r->private_key, peer.remote_static_x25519);
    if (!dh_se_opt) return std::nullopt;
    auto dh_se = *dh_se_opt;
    if (!MixKey(C, dh_se)) {
        secure_zero(dh_se);
        return std::nullopt;
    }
    secure_zero(dh_se);

    // Zero responder ephemeral private key — no longer needed after DH ops
    secure_zero(e_r->private_key);

    // Step 6: ML-KEM KEM #3 — encapsulate to initiator's static ML-KEM key
    auto encaps_se = core::cryptography::ml_kem::Encapsulate(
        remote_static_mlkem,
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!encaps_se) return std::nullopt;
    if (!MixKey(C, ConstByteSpan{encaps_se->shared_secret.data(), encaps_se->shared_secret.size()})) {
        secure_zero(encaps_se->shared_secret.data(), encaps_se->shared_secret.size());
        return std::nullopt;
    }
    secure_zero(encaps_se->shared_secret.data(), encaps_se->shared_secret.size());
    MixHash(H, ConstByteSpan{encaps_se->ciphertext.data(), encaps_se->ciphertext.size()});

    // Step 7: Mix PSK — KDF3 produces new C, a hash-mix value tau, and an encryption key
    auto kdf3 = KDF3(C, peer.preshared_key);
    if (!kdf3) return std::nullopt;
    C = std::get<0>(*kdf3);
    Blake3Hash tau     = std::get<1>(*kdf3);
    Blake3Hash enc_key = std::get<2>(*kdf3);
    secure_zero(std::get<1>(*kdf3));
    secure_zero(std::get<2>(*kdf3));
    MixHash(H, tau);
    secure_zero(tau);

    // Step 8: Encrypt empty payload — the 16-byte tag authenticates the full transcript
    auto encrypted_empty = EncryptAndHash(H, enc_key, ConstByteSpan{});
    secure_zero(enc_key);
    if (!encrypted_empty || encrypted_empty->size() != 16) return std::nullopt;

    // Step 9: Assign sender index
    const std::uint32_t local_index = index_table.NewIndex(&peer, &peer.handshake);

    // Step 10: Build response message
    ResponseMsg msg{};
    msg.sender_index   = local_index;
    msg.receiver_index = remote_index;
    std::copy(e_r->public_key.begin(), e_r->public_key.end(),
              msg.ephemeral_x25519.begin());
    std::copy(encaps_ee->ciphertext.begin(), encaps_ee->ciphertext.end(),
              msg.kem_ciphertext_ee.begin());
    std::copy(encaps_se->ciphertext.begin(), encaps_se->ciphertext.end(),
              msg.kem_ciphertext_se.begin());
    std::copy(encrypted_empty->begin(), encrypted_empty->end(),
              msg.encrypted_empty.begin());
    // mac1/mac2 are zero — filled by MAC system (DG-244) before sending

    // Step 11: Commit state
    {
        std::lock_guard lock(peer.handshake.mutex);
        peer.handshake.chaining_key = C;
        peer.handshake.hash         = H;
        peer.handshake.local_index  = local_index;
        peer.handshake.state        = HandshakeStateEnum::ResponseCreated;
    }

    return SerializeResponse(msg);
}

// ============================================================================
// Stubs for remaining message handlers
// ============================================================================

bool ConsumeMessageResponse(ConstByteSpan msg, Peer& peer, IndexTable& index_table) {
    // Step 1: Parse response
    auto response = DeserializeResponse(msg.data(), msg.size());
    if (!response) return false;

    // Step 2: Verify receiver_index maps to this peer
    auto entry = index_table.Lookup(response->receiver_index);
    if (!entry || entry->peer != &peer) return false;

    // Step 3: Verify state and load C, H, ephemeral keys under lock
    Blake3Hash C, H;
    std::array<std::uint8_t, 32>   e_i_priv{};
    std::array<std::uint8_t, 2400> e_i_mlkem_dk{};
    {
        std::lock_guard lock(peer.handshake.mutex);
        if (peer.handshake.state != HandshakeStateEnum::InitiationCreated)
            return false;
        C = peer.handshake.chaining_key;
        H = peer.handshake.hash;
        e_i_priv     = peer.handshake.local_ephemeral_x25519_private;
        e_i_mlkem_dk = peer.handshake.local_ephemeral_mlkem_dk;
    }

    // TODO: DG-244 — mac1 verification

    // Step 5: Mix E_r_pub into transcript
    if (!MixKey(C, response->ephemeral_x25519)) {
        secure_zero(e_i_priv);
        secure_zero(e_i_mlkem_dk);
        return false;
    }
    MixHash(H, response->ephemeral_x25519);

    // Step 6: DH #3 (ee) — initiator ephemeral × responder ephemeral
    auto dh_ee_opt = core::cryptography::x25519::DeriveSharedSecret(
        e_i_priv, response->ephemeral_x25519);
    secure_zero(e_i_priv);
    if (!dh_ee_opt) {
        secure_zero(e_i_mlkem_dk);
        return false;
    }
    auto dh_ee = *dh_ee_opt;
    if (!MixKey(C, dh_ee)) {
        secure_zero(dh_ee);
        secure_zero(e_i_mlkem_dk);
        return false;
    }
    secure_zero(dh_ee);

    // Step 7: KEM #2 — decapsulate ct_ee with initiator's ephemeral ML-KEM DK
    auto e_dk_ptr = RebuildMlKemKey(e_i_mlkem_dk);
    secure_zero(e_i_mlkem_dk);
    if (!e_dk_ptr) return false;
    auto ss_kem_ee = core::cryptography::ml_kem::Decapsulate(
        e_dk_ptr.get(), response->kem_ciphertext_ee);
    e_dk_ptr.reset();
    if (!ss_kem_ee) return false;
    if (!MixKey(C, ConstByteSpan{ss_kem_ee->data(), ss_kem_ee->size()})) {
        secure_zero(ss_kem_ee->data(), ss_kem_ee->size());
        return false;
    }
    secure_zero(ss_kem_ee->data(), ss_kem_ee->size());
    MixHash(H, response->kem_ciphertext_ee);

    // Step 8: DH #4 (se) — initiator static × responder ephemeral
    auto dh_se_opt = core::cryptography::x25519::DeriveSharedSecret(
        peer.local_static_x25519_private, response->ephemeral_x25519);
    if (!dh_se_opt) return false;
    auto dh_se = *dh_se_opt;
    if (!MixKey(C, dh_se)) {
        secure_zero(dh_se);
        return false;
    }
    secure_zero(dh_se);

    // Step 9: KEM #3 — decapsulate ct_se with initiator's static ML-KEM DK
    auto s_dk_ptr = RebuildMlKemKey(peer.local_static_mlkem_dk);
    if (!s_dk_ptr) return false;
    auto ss_kem_se = core::cryptography::ml_kem::Decapsulate(
        s_dk_ptr.get(), response->kem_ciphertext_se);
    s_dk_ptr.reset();
    if (!ss_kem_se) return false;
    if (!MixKey(C, ConstByteSpan{ss_kem_se->data(), ss_kem_se->size()})) {
        secure_zero(ss_kem_se->data(), ss_kem_se->size());
        return false;
    }
    secure_zero(ss_kem_se->data(), ss_kem_se->size());
    MixHash(H, response->kem_ciphertext_se);

    // Step 10: Mix PSK
    auto kdf3 = KDF3(C, peer.preshared_key);
    if (!kdf3) return false;
    C = std::get<0>(*kdf3);
    Blake3Hash tau     = std::get<1>(*kdf3);
    Blake3Hash dec_key = std::get<2>(*kdf3);
    secure_zero(std::get<1>(*kdf3));
    secure_zero(std::get<2>(*kdf3));
    MixHash(H, tau);
    secure_zero(tau);

    // Step 11: Decrypt and verify empty payload — authentication gate
    auto dec_empty = DecryptAndHash(H, dec_key, response->encrypted_empty);
    secure_zero(dec_key);
    if (!dec_empty) return false;

    // Step 12 & 13: Commit state and zero ephemeral private keys
    {
        std::lock_guard lock(peer.handshake.mutex);
        peer.handshake.chaining_key = C;
        peer.handshake.hash         = H;
        peer.handshake.remote_index = response->sender_index;
        peer.handshake.state        = HandshakeStateEnum::ResponseConsumed;
        secure_zero(peer.handshake.local_ephemeral_x25519_private);
        secure_zero(peer.handshake.local_ephemeral_mlkem_dk);
    }

    return true;
}

bool DeriveSessionKeys(Peer& peer, IndexTable& index_table, bool is_initiator) {
    // Load C and index fields under lock
    Blake3Hash C{};
    std::uint32_t local_index  = 0;
    std::uint32_t remote_index = 0;
    {
        std::lock_guard lock(peer.handshake.mutex);
        const auto expected = is_initiator
            ? HandshakeStateEnum::ResponseConsumed
            : HandshakeStateEnum::ResponseCreated;
        if (peer.handshake.state != expected) return false;

        C            = peer.handshake.chaining_key;
        local_index  = peer.handshake.local_index;
        remote_index = peer.handshake.remote_index;
    }

    // Derive two transport keys from the final chaining key
    auto kdf2 = KDF2(C, ConstByteSpan{});
    secure_zero(C);
    if (!kdf2) return false;

    Blake3Hash T0 = std::get<0>(*kdf2);
    Blake3Hash T1 = std::get<1>(*kdf2);
    secure_zero(std::get<0>(*kdf2));
    secure_zero(std::get<1>(*kdf2));

    // Build keypair — initiator sends on T0, receives on T1; responder is swapped
    auto kp = std::make_unique<Keypair>();
    if (is_initiator) {
        kp->send_key    = T0;
        kp->receive_key = T1;
    } else {
        kp->receive_key = T0;
        kp->send_key    = T1;
    }
    secure_zero(T0);
    secure_zero(T1);

    kp->is_initiator = is_initiator;
    kp->created      = std::chrono::system_clock::now();
    kp->local_index  = local_index;
    kp->remote_index = remote_index;

    // Register keypair in the index table (replaces handshake entry)
    Keypair* kp_raw = kp.get();
    index_table.SwapHandshakeToKeypair(local_index, kp_raw);

    // Install keypair into the peer's session slots
    if (is_initiator) {
        peer.keypairs.SetCurrent(std::move(kp));
    } else {
        peer.keypairs.SetNext(std::move(kp));
    }

    // Security-critical cleanup — zero handshake state, preserve anti-replay fields
    {
        std::lock_guard lock(peer.handshake.mutex);
        secure_zero(peer.handshake.chaining_key);
        secure_zero(peer.handshake.hash);
        secure_zero(peer.handshake.local_ephemeral_x25519_private);
        secure_zero(peer.handshake.local_ephemeral_mlkem_dk);
        peer.handshake.state = HandshakeStateEnum::Zeroed;
        // last_timestamp and precomputed_static_static are intentionally preserved
    }

    return true;
}

} // namespace core::handshake
