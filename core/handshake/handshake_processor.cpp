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

#include <mutex>

namespace core::handshake {

using core::utils::secure_zero;

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

bool ConsumeMessageInitiation(ConstByteSpan msg, Peer& peer) {
    (void)msg; (void)peer;
    return false; // DG-240
}

std::optional<std::vector<std::uint8_t>>
CreateMessageResponse(Peer& peer, IndexTable& index_table) {
    (void)peer; (void)index_table;
    return std::nullopt; // DG-242
}

bool ConsumeMessageResponse(ConstByteSpan msg, Peer& peer, IndexTable& index_table) {
    (void)msg; (void)peer; (void)index_table;
    return false; // DG-243
}

bool DeriveSessionKeys(Peer& peer, IndexTable& index_table, bool is_initiator) {
    (void)peer; (void)index_table; (void)is_initiator;
    return false; // DG-250
}

} // namespace core::handshake
