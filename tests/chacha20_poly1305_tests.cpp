#include "tests.h"
#include "chacha20_poly1305.hpp"

#include <algorithm>
#include <cstring>
#include <string>

using namespace core::cryptography::chacha20_poly1305;

// ============================================================================
// GenerateKey tests
// ============================================================================

// GenerateKey returns a value
bool ChaCha20Test_GenerateKey_Succeeds() {
    auto key = GenerateKey();
    return test_helper("1", std::to_string(key.has_value()));
}

// Two generated keys should differ
bool ChaCha20Test_GenerateKey_Unique() {
    auto k1 = GenerateKey();
    auto k2 = GenerateKey();
    if (!k1 || !k2) return test_helper("keygen", "nullopt");

    bool different = (*k1 != *k2);
    return test_helper("1", std::to_string(different));
}

// ============================================================================
// GenerateNonce tests
// ============================================================================

// GenerateNonce returns a value
bool ChaCha20Test_GenerateNonce_Succeeds() {
    auto nonce = GenerateNonce();
    return test_helper("1", std::to_string(nonce.has_value()));
}

// Two generated nonces should differ
bool ChaCha20Test_GenerateNonce_Unique() {
    auto n1 = GenerateNonce();
    auto n2 = GenerateNonce();
    if (!n1 || !n2) return test_helper("noncegen", "nullopt");

    bool different = (*n1 != *n2);
    return test_helper("1", std::to_string(different));
}

// ============================================================================
// Encrypt tests
// ============================================================================

// Basic encryption succeeds and produces output
bool ChaCha20Test_Encrypt_Succeeds() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    auto result = Encrypt(plaintext, *key, *nonce);

    return test_helper("1", std::to_string(result.has_value()));
}

// Ciphertext length equals plaintext length (stream cipher property)
bool ChaCha20Test_Encrypt_CiphertextLength() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto result = Encrypt(plaintext, *key, *nonce);
    if (!result) return test_helper("encrypt", "nullopt");

    return test_helper(std::to_string(plaintext.size()), std::to_string(result->ciphertext.size()));
}

// Ciphertext should differ from plaintext
bool ChaCha20Test_Encrypt_CiphertextDiffers() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    auto result = Encrypt(plaintext, *key, *nonce);
    if (!result) return test_helper("encrypt", "nullopt");

    bool different = (plaintext != result->ciphertext);
    return test_helper("1", std::to_string(different));
}

// Encrypting empty plaintext should fail (nullopt)
bool ChaCha20Test_Encrypt_EmptyPlaintext() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext{};
    auto result = Encrypt(plaintext, *key, *nonce);

    return test_helper("0", std::to_string(result.has_value()));
}

// Same plaintext + key + nonce produces identical ciphertext (deterministic)
bool ChaCha20Test_Encrypt_Deterministic() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'T', 'e', 's', 't'};
    auto r1 = Encrypt(plaintext, *key, *nonce);
    auto r2 = Encrypt(plaintext, *key, *nonce);
    if (!r1 || !r2) return test_helper("encrypt", "nullopt");

    bool ct_match = (r1->ciphertext == r2->ciphertext);
    bool tag_match = (r1->tag == r2->tag);
    return test_helper("1", std::to_string(ct_match && tag_match));
}

// Different nonces produce different ciphertext
bool ChaCha20Test_Encrypt_DifferentNonce() {
    auto key = GenerateKey();
    auto n1 = GenerateNonce();
    auto n2 = GenerateNonce();
    if (!key || !n1 || !n2) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'D', 'a', 't', 'a'};
    auto r1 = Encrypt(plaintext, *key, *n1);
    auto r2 = Encrypt(plaintext, *key, *n2);
    if (!r1 || !r2) return test_helper("encrypt", "nullopt");

    bool different = (r1->ciphertext != r2->ciphertext);
    return test_helper("1", std::to_string(different));
}

// Different keys produce different ciphertext
bool ChaCha20Test_Encrypt_DifferentKey() {
    auto k1 = GenerateKey();
    auto k2 = GenerateKey();
    auto nonce = GenerateNonce();
    if (!k1 || !k2 || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'D', 'a', 't', 'a'};
    auto r1 = Encrypt(plaintext, *k1, *nonce);
    auto r2 = Encrypt(plaintext, *k2, *nonce);
    if (!r1 || !r2) return test_helper("encrypt", "nullopt");

    bool different = (r1->ciphertext != r2->ciphertext);
    return test_helper("1", std::to_string(different));
}

// ============================================================================
// Decrypt tests
// ============================================================================

// Basic roundtrip: encrypt then decrypt recovers plaintext
bool ChaCha20Test_Roundtrip_Basic() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'R', 'o', 'u', 'n', 'd', 't', 'r', 'i', 'p'};
    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(plaintext == *dec));
}

// Roundtrip with AAD
bool ChaCha20Test_Roundtrip_WithAAD() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'P', 'a', 'y', 'l', 'o', 'a', 'd'};
    std::vector<std::uint8_t> aad = {'H', 'e', 'a', 'd', 'e', 'r'};

    auto enc = Encrypt(plaintext, *key, *nonce, aad);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce, aad);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(plaintext == *dec));
}

// Roundtrip with a larger payload (4 KB)
bool ChaCha20Test_Roundtrip_4KB() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext(4096);
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(plaintext == *dec));
}


// Roundtrip with 4 MB payload
bool ChaCha20Test_Roundtrip_4MB() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    constexpr std::size_t size = 4ULL * 1024 * 1024; // 4 MB
    std::vector<std::uint8_t> plaintext(size);
    for (std::size_t i = 0; i < size; ++i) {
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(plaintext == *dec));
}

// Roundtrip with 1 GB payload
bool ChaCha20Test_Roundtrip_1GB() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    constexpr std::size_t size = 1ULL * 1024 * 1024 * 1024; // 1 GB
    std::vector<std::uint8_t> plaintext;

    try {
        plaintext.resize(size);
    } catch (const std::bad_alloc&) {
        // Not enough memory to run this test so treat it as inconclusive pass
        std::cout << "\n  [SKIP] insufficient memory for 1 GB allocation\n";
        return true;
    }

    for (std::size_t i = 0; i < size; ++i) {
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    // Free plaintext early to reduce peak memory (need ~3x 1 GB otherwise)
    std::vector<std::uint8_t> original = std::move(plaintext);
    plaintext.clear();
    plaintext.shrink_to_fit();

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(original == *dec));
}

// Roundtrip with single byte
bool ChaCha20Test_Roundtrip_SingleByte() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {0x42};
    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    if (!dec) return test_helper("decrypt", "nullopt");

    return test_helper("1", std::to_string(plaintext == *dec));
}

// Decrypting empty ciphertext should fail
bool ChaCha20Test_Decrypt_EmptyCiphertext() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> ciphertext{};
    Tag tag{};
    auto dec = Decrypt(ciphertext, tag, *key, *nonce);

    return test_helper("0", std::to_string(dec.has_value()));
}

// ============================================================================
// Authentication failure tests
// ============================================================================

// Wrong key -> auth failure
bool ChaCha20Test_Auth_WrongKey() {
    auto k1 = GenerateKey();
    auto k2 = GenerateKey();
    auto nonce = GenerateNonce();
    if (!k1 || !k2 || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    auto enc = Encrypt(plaintext, *k1, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *k2, *nonce);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Wrong nonce -> auth failure
bool ChaCha20Test_Auth_WrongNonce() {
    auto key = GenerateKey();
    auto n1 = GenerateNonce();
    auto n2 = GenerateNonce();
    if (!key || !n1 || !n2) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    auto enc = Encrypt(plaintext, *key, *n1);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *n2);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Tampered ciphertext -> auth failure
bool ChaCha20Test_Auth_TamperedCiphertext() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    // Flip a bit in the ciphertext
    enc->ciphertext[0] ^= 0x01;

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Tampered tag -> auth failure
bool ChaCha20Test_Auth_TamperedTag() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    // Flip a bit in the tag
    enc->tag[0] ^= 0x01;

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Wrong AAD -> auth failure
bool ChaCha20Test_Auth_WrongAAD() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'P', 'a', 'y', 'l', 'o', 'a', 'd'};
    std::vector<std::uint8_t> aad1 = {'H', 'e', 'a', 'd', 'e', 'r'};
    std::vector<std::uint8_t> aad2 = {'F', 'a', 'k', 'e', '!', '!'};

    auto enc = Encrypt(plaintext, *key, *nonce, aad1);
    if (!enc) return test_helper("encrypt", "nullopt");

    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce, aad2);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Missing AAD on decrypt when AAD was used on encrypt -> auth failure
bool ChaCha20Test_Auth_MissingAAD() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'P', 'a', 'y', 'l', 'o', 'a', 'd'};
    std::vector<std::uint8_t> aad = {'H', 'e', 'a', 'd', 'e', 'r'};

    auto enc = Encrypt(plaintext, *key, *nonce, aad);
    if (!enc) return test_helper("encrypt", "nullopt");

    // Decrypt without AAD
    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce);
    return test_helper("0", std::to_string(dec.has_value()));
}

// Spurious AAD on decrypt when none was used on encrypt -> auth failure
bool ChaCha20Test_Auth_SpuriousAAD() {
    auto key = GenerateKey();
    auto nonce = GenerateNonce();
    if (!key || !nonce) return test_helper("setup", "nullopt");

    std::vector<std::uint8_t> plaintext = {'P', 'a', 'y', 'l', 'o', 'a', 'd'};
    std::vector<std::uint8_t> aad = {'E', 'x', 't', 'r', 'a'};

    auto enc = Encrypt(plaintext, *key, *nonce);
    if (!enc) return test_helper("encrypt", "nullopt");

    // Decrypt with unexpected AAD
    auto dec = Decrypt(enc->ciphertext, enc->tag, *key, *nonce, aad);
    return test_helper("0", std::to_string(dec.has_value()));
}