#ifndef _PQVPN_TESTS_X25519_TESTS_HPP_
#define _PQVPN_TESTS_X25519_TESTS_HPP_

#include "test_utils.hpp"
#include "x25519.hpp"

#include <algorithm>
#include <cstring>

// Namespace alias instead of `using namespace` to avoid ambiguous lookup with
// core::cryptography::ml_kem, which also exports GenerateKeyPair / KeyPair /
// kSharedSecretBytes when both test headers are in the same translation unit.
namespace x25519 = core::cryptography::x25519;

// ============================================================================
// GenerateKeyPair tests
// ============================================================================

// GenerateKeyPair returns a value
bool X25519Test_GenerateKeyPair_Succeeds() {
    auto kp = x25519::GenerateKeyPair();
    return test_helper("1", std::to_string(kp.has_value()));
}

// Public and private keys within a pair should differ
bool X25519Test_GenerateKeyPair_PublicDiffersFromPrivate() {
    auto kp = x25519::GenerateKeyPair();
    if (!kp) return test_helper("setup", "nullopt");

    bool different = (kp->private_key != kp->public_key);
    return test_helper("1", std::to_string(different));
}

// Two generated key pairs should have distinct private keys
bool X25519Test_GenerateKeyPair_UniquePrivateKeys() {
    auto kp1 = x25519::GenerateKeyPair();
    auto kp2 = x25519::GenerateKeyPair();
    if (!kp1 || !kp2) return test_helper("setup", "nullopt");

    bool different = (kp1->private_key != kp2->private_key);
    return test_helper("1", std::to_string(different));
}

// Two generated key pairs should have distinct public keys
bool X25519Test_GenerateKeyPair_UniquePublicKeys() {
    auto kp1 = x25519::GenerateKeyPair();
    auto kp2 = x25519::GenerateKeyPair();
    if (!kp1 || !kp2) return test_helper("setup", "nullopt");

    bool different = (kp1->public_key != kp2->public_key);
    return test_helper("1", std::to_string(different));
}

// Private key should be exactly kPrivateKeyBytes long
bool X25519Test_GenerateKeyPair_PrivateKeySize() {
    auto kp = x25519::GenerateKeyPair();
    if (!kp) return test_helper("setup", "nullopt");

    return test_helper(
        std::to_string(x25519::kPrivateKeyBytes),
        std::to_string(kp->private_key.size())
    );
}

// Public key should be exactly kPublicKeyBytes long
bool X25519Test_GenerateKeyPair_PublicKeySize() {
    auto kp = x25519::GenerateKeyPair();
    if (!kp) return test_helper("setup", "nullopt");

    return test_helper(
        std::to_string(x25519::kPublicKeyBytes),
        std::to_string(kp->public_key.size())
    );
}

// ============================================================================
// PublicKeyFromPrivate tests
// ============================================================================

// Deriving the public key from a private key matches the one in the key pair
bool X25519Test_PublicKeyFromPrivate_MatchesKeyPair() {
    auto kp = x25519::GenerateKeyPair();
    if (!kp) return test_helper("setup", "nullopt");

    auto derived_pub = x25519::PublicKeyFromPrivate(kp->private_key);
    if (!derived_pub) return test_helper("derive", "nullopt");

    bool match = (*derived_pub == kp->public_key);
    return test_helper("1", std::to_string(match));
}

// Two calls with the same private key produce the same public key (deterministic)
bool X25519Test_PublicKeyFromPrivate_Deterministic() {
    auto kp = x25519::GenerateKeyPair();
    if (!kp) return test_helper("setup", "nullopt");

    auto pub1 = x25519::PublicKeyFromPrivate(kp->private_key);
    auto pub2 = x25519::PublicKeyFromPrivate(kp->private_key);
    if (!pub1 || !pub2) return test_helper("derive", "nullopt");

    return test_helper("1", std::to_string(*pub1 == *pub2));
}

// Different private keys yield different public keys
bool X25519Test_PublicKeyFromPrivate_UniquePerPrivateKey() {
    auto kp1 = x25519::GenerateKeyPair();
    auto kp2 = x25519::GenerateKeyPair();
    if (!kp1 || !kp2) return test_helper("setup", "nullopt");

    auto pub1 = x25519::PublicKeyFromPrivate(kp1->private_key);
    auto pub2 = x25519::PublicKeyFromPrivate(kp2->private_key);
    if (!pub1 || !pub2) return test_helper("derive", "nullopt");

    bool different = (*pub1 != *pub2);
    return test_helper("1", std::to_string(different));
}

// ============================================================================
// DeriveSharedSecret tests
// ============================================================================

// Basic shared secret derivation succeeds
bool X25519Test_DeriveSharedSecret_Succeeds() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b) return test_helper("setup", "nullopt");

    auto secret = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    return test_helper("1", std::to_string(secret.has_value()));
}

// Shared secret size is exactly kSharedSecretBytes
bool X25519Test_DeriveSharedSecret_Size() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b) return test_helper("setup", "nullopt");

    auto secret = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    if (!secret) return test_helper("derive", "nullopt");

    return test_helper(
        std::to_string(x25519::kSharedSecretBytes),
        std::to_string(secret->size())
    );
}

// ECDH is commutative: A's secret with B's public == B's secret with A's public
bool X25519Test_DeriveSharedSecret_Commutative() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b) return test_helper("setup", "nullopt");

    auto secret_ab = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    auto secret_ba = x25519::DeriveSharedSecret(kp_b->private_key, kp_a->public_key);
    if (!secret_ab || !secret_ba) return test_helper("derive", "nullopt");

    bool match = (*secret_ab == *secret_ba);
    return test_helper("1", std::to_string(match));
}

// Shared secret differs from both participants' public keys
bool X25519Test_DeriveSharedSecret_DiffersFromPublicKeys() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b) return test_helper("setup", "nullopt");

    auto secret = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    if (!secret) return test_helper("derive", "nullopt");

    bool differs_a = (*secret != kp_a->public_key);
    bool differs_b = (*secret != kp_b->public_key);
    return test_helper("1", std::to_string(differs_a && differs_b));
}

// Derivation is deterministic: same inputs → same secret
bool X25519Test_DeriveSharedSecret_Deterministic() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b) return test_helper("setup", "nullopt");

    auto s1 = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    auto s2 = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    if (!s1 || !s2) return test_helper("derive", "nullopt");

    return test_helper("1", std::to_string(*s1 == *s2));
}

// Different peer public keys yield different secrets
bool X25519Test_DeriveSharedSecret_DifferentPeerGivesDifferentSecret() {
    auto kp_a  = x25519::GenerateKeyPair();
    auto kp_b1 = x25519::GenerateKeyPair();
    auto kp_b2 = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b1 || !kp_b2) return test_helper("setup", "nullopt");

    auto s1 = x25519::DeriveSharedSecret(kp_a->private_key, kp_b1->public_key);
    auto s2 = x25519::DeriveSharedSecret(kp_a->private_key, kp_b2->public_key);
    if (!s1 || !s2) return test_helper("derive", "nullopt");

    bool different = (*s1 != *s2);
    return test_helper("1", std::to_string(different));
}

// Wrong private key → different secret (authentication property)
bool X25519Test_DeriveSharedSecret_WrongPrivateKey() {
    auto kp_a1 = x25519::GenerateKeyPair();
    auto kp_a2 = x25519::GenerateKeyPair(); // impostor
    auto kp_b  = x25519::GenerateKeyPair();
    if (!kp_a1 || !kp_a2 || !kp_b) return test_helper("setup", "nullopt");

    auto s_real     = x25519::DeriveSharedSecret(kp_a1->private_key, kp_b->public_key);
    auto s_impostor = x25519::DeriveSharedSecret(kp_a2->private_key, kp_b->public_key);
    if (!s_real || !s_impostor) return test_helper("derive", "nullopt");

    bool different = (*s_real != *s_impostor);
    return test_helper("1", std::to_string(different));
}

// Three-party: each pair derives independent secrets (no cross-contamination)
bool X25519Test_DeriveSharedSecret_ThreePartyIndependent() {
    auto kp_a = x25519::GenerateKeyPair();
    auto kp_b = x25519::GenerateKeyPair();
    auto kp_c = x25519::GenerateKeyPair();
    if (!kp_a || !kp_b || !kp_c) return test_helper("setup", "nullopt");

    auto s_ab = x25519::DeriveSharedSecret(kp_a->private_key, kp_b->public_key);
    auto s_ac = x25519::DeriveSharedSecret(kp_a->private_key, kp_c->public_key);
    auto s_bc = x25519::DeriveSharedSecret(kp_b->private_key, kp_c->public_key);
    if (!s_ab || !s_ac || !s_bc) return test_helper("derive", "nullopt");

    bool all_different = (*s_ab != *s_ac) && (*s_ab != *s_bc) && (*s_ac != *s_bc);
    return test_helper("1", std::to_string(all_different));
}

#endif // _PQVPN_TESTS_X25519_TESTS_HPP_
