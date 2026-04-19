#ifndef _PQVPN_TESTS_ML_KEM_TESTS_HPP_
#define _PQVPN_TESTS_ML_KEM_TESTS_HPP_

#include "test_utils.hpp"
#include "ml_kem.hpp"

// Namespace alias avoids polluting global scope with GenerateKeyPair / KeyPair,
// which also exist in core::cryptography::x25519 — keeping both test headers in
// the same translation unit would otherwise create ambiguous name lookups.
namespace ml_kem = core::cryptography::ml_kem;

static std::string MlKemBytesMatch(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    if (a.size() != b.size()) return "size_mismatch";
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return "mismatch";
    }
    return "match";
}

// Generate a key pair, encapsulate, decapsulate, shared secrets must match
bool MlKemTest_Roundtrip_768() {
    auto kp = ml_kem::GenerateKeyPair();
    if (!kp) return test_helper("keygen", "nullopt");

    auto enc = ml_kem::Encapsulate(kp->public_key);
    if (!enc) return test_helper("encapsulate", "nullopt");

    auto ss = ml_kem::Decapsulate(*kp, enc->ciphertext);
    if (!ss) return test_helper("decapsulate", "nullopt");

    return test_helper("match", MlKemBytesMatch(enc->shared_secret, *ss));
}

// FIPS 203: shared secret is always 32 bytes
bool MlKemTest_SharedSecretSize() {
    auto kp = ml_kem::GenerateKeyPair();
    if (!kp) return test_helper("keygen", "nullopt");

    auto enc = ml_kem::Encapsulate(kp->public_key);
    if (!enc) return test_helper("encapsulate", "nullopt");

    auto ss = ml_kem::Decapsulate(*kp, enc->ciphertext);
    if (!ss) return test_helper("decapsulate", "nullopt");

    bool both_32 = (enc->shared_secret.size() == 32) && (ss->size() == 32);
    return test_helper("1", std::to_string(both_32));
}

// Two encapsulations against the same key produce different shared secrets
bool MlKemTest_EncapsulateUniqueness() {
    auto kp = ml_kem::GenerateKeyPair();
    if (!kp) return test_helper("keygen", "nullopt");

    auto enc1 = ml_kem::Encapsulate(kp->public_key);
    auto enc2 = ml_kem::Encapsulate(kp->public_key);
    if (!enc1 || !enc2) return test_helper("encapsulate", "nullopt");

    return test_helper("mismatch", MlKemBytesMatch(enc1->shared_secret, enc2->shared_secret));
}

// Decapsulating with the wrong private key must NOT recover the original secret
// (FIPS 203 implicit rejection: returns a pseudorandom secret, not an error)
bool MlKemTest_WrongKeyImplicitRejection() {
    auto kp_alice = ml_kem::GenerateKeyPair();
    auto kp_bob   = ml_kem::GenerateKeyPair();
    if (!kp_alice || !kp_bob) return test_helper("keygen", "nullopt");

    auto enc = ml_kem::Encapsulate(kp_alice->public_key);
    if (!enc) return test_helper("encapsulate", "nullopt");

    auto ss = ml_kem::Decapsulate(*kp_bob, enc->ciphertext);
    if (!ss) return test_helper("decapsulate", "nullopt");

    return test_helper("mismatch", MlKemBytesMatch(enc->shared_secret, *ss));
}

#endif // _PQVPN_TESTS_ML_KEM_TESTS_HPP_
