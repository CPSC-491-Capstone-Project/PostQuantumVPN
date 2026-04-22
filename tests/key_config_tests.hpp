#ifndef _PQVPN_TESTS_KEY_CONFIG_TESTS_HPP_
#define _PQVPN_TESTS_KEY_CONFIG_TESTS_HPP_

#include "test_utils.hpp"
#include "key_config.hpp"
#include "x25519.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <string>

namespace kc     = core::config;
namespace x25519 = core::cryptography::x25519;

static void kc_remove(const char* p) { std::remove(p); }

// Creates the config file on first run
bool KeyConfigTest_LoadOrGenerate_CreatesFile() {
    const char* path = "/tmp/pqvpn_test_create.conf";
    kc_remove(path);
    auto keys = kc::LoadOrGenerateKeys(path);
    bool exists = std::ifstream(path).good();
    kc_remove(path);
    if (!keys) return test_helper("setup", "nullopt");
    return test_helper("1", std::to_string(exists));
}

// Generated keys are non-zero
bool KeyConfigTest_LoadOrGenerate_KeysNonZero() {
    const char* path = "/tmp/pqvpn_test_nonzero.conf";
    kc_remove(path);
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!keys) return test_helper("setup", "nullopt");
    bool nonzero = std::any_of(keys->x25519_pub.begin(), keys->x25519_pub.end(),
                               [](uint8_t b){ return b != 0; });
    return test_helper("1", std::to_string(nonzero));
}

// Second call with same path loads identical public keys
bool KeyConfigTest_LoadOrGenerate_PublicKeyPersists() {
    const char* path = "/tmp/pqvpn_test_pub_persist.conf";
    kc_remove(path);
    auto k1 = kc::LoadOrGenerateKeys(path);
    auto k2 = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!k1 || !k2) return test_helper("setup", "nullopt");
    return test_helper("1", std::to_string(k1->x25519_pub == k2->x25519_pub
                                        && k1->mlkem_ek   == k2->mlkem_ek));
}

// Second call with same path loads identical private keys
bool KeyConfigTest_LoadOrGenerate_PrivateKeyPersists() {
    const char* path = "/tmp/pqvpn_test_priv_persist.conf";
    kc_remove(path);
    auto k1 = kc::LoadOrGenerateKeys(path);
    auto k2 = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!k1 || !k2) return test_helper("setup", "nullopt");
    return test_helper("1", std::to_string(k1->x25519_priv == k2->x25519_priv
                                        && k1->mlkem_dk    == k2->mlkem_dk));
}

// Stored public key is consistent with the stored private key
bool KeyConfigTest_LoadOrGenerate_PublicMatchesPrivate() {
    const char* path = "/tmp/pqvpn_test_pub_match.conf";
    kc_remove(path);
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!keys) return test_helper("setup", "nullopt");
    auto derived = x25519::PublicKeyFromPrivate(keys->x25519_priv);
    if (!derived) return test_helper("setup", "pub derivation failed");
    return test_helper("1", std::to_string(*derived == keys->x25519_pub));
}

// Two different paths produce different key pairs
bool KeyConfigTest_LoadOrGenerate_UniqueKeysPerFile() {
    const char* p1 = "/tmp/pqvpn_test_unique1.conf";
    const char* p2 = "/tmp/pqvpn_test_unique2.conf";
    kc_remove(p1); kc_remove(p2);
    auto k1 = kc::LoadOrGenerateKeys(p1);
    auto k2 = kc::LoadOrGenerateKeys(p2);
    kc_remove(p1); kc_remove(p2);
    if (!k1 || !k2) return test_helper("setup", "nullopt");
    return test_helper("1", std::to_string(k1->x25519_pub != k2->x25519_pub));
}

// Completely invalid file returns nullopt
bool KeyConfigTest_LoadOrGenerate_NulloptOnBadFile() {
    const char* path = "/tmp/pqvpn_test_bad.conf";
    { std::ofstream f(path); f << "not = valid\njunk = data\n"; }
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    return test_helper("0", std::to_string(keys.has_value()));
}

// File with only partial keys (missing ML-KEM) returns nullopt
bool KeyConfigTest_LoadOrGenerate_NulloptOnPartialFile() {
    const char* path = "/tmp/pqvpn_test_partial.conf";
    {
        std::ofstream f(path);
        f << "x25519_private = " << std::string(64, 'a') << "\n";
        f << "x25519_public = "  << std::string(64, 'b') << "\n";
    }
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    return test_helper("0", std::to_string(keys.has_value()));
}

// ML-KEM EK in saved file is the correct size (1184 bytes = 2368 hex chars)
bool KeyConfigTest_LoadOrGenerate_MlKemEkSize() {
    const char* path = "/tmp/pqvpn_test_ek_size.conf";
    kc_remove(path);
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!keys) return test_helper("setup", "nullopt");
    return test_helper("1184", std::to_string(keys->mlkem_ek.size()));
}

// ML-KEM DK in saved file is the correct size (2400 bytes)
bool KeyConfigTest_LoadOrGenerate_MlKemDkSize() {
    const char* path = "/tmp/pqvpn_test_dk_size.conf";
    kc_remove(path);
    auto keys = kc::LoadOrGenerateKeys(path);
    kc_remove(path);
    if (!keys) return test_helper("setup", "nullopt");
    return test_helper("2400", std::to_string(keys->mlkem_dk.size()));
}

#endif // _PQVPN_TESTS_KEY_CONFIG_TESTS_HPP_
