#include "tests.h"
#include "timer.hpp"

#include <string_view>
#include <iostream>
#include <iomanip>

static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

static const char* GREEN = "\033[32m";
static const char* RED = "\033[31m";
static const char* CYAN = "\033[36m";
static const char* RESET = "\033[0m";

void Run(bool (*test)(), std::string_view name) {
    total_tests++;
    core::utils::Timer timer;

    std::cout << CYAN << "[TEST] " << RESET << std::left << std::setw(40) << name;

    timer.Start();
    bool result = test();
    timer.Stop();

    if (result) {
        passed_tests++;
        std::cout << GREEN << "[PASS]" << RESET;
    } else {
        failed_tests++;
        std::cout << RED   << "[FAIL]" << RESET;
    }

    std::cout << "  " << timer.ElapsedStr() << "\n";
}

int main(int argc, char* argv[]) {

    (void)argc;
    (void)argv;

    std::cout << "========================================\n";
    std::cout << "Running Test Suite\n";
    std::cout << "========================================\n\n";

    // =============================================================================
    // Random Tests
    // =============================================================================
    
    std::cout << "\n";
    Run(RandomTest_SingletonInit, "Random: Init");
    Run(RandomTest_ZeroBytes, "Random: 0 bytes");
    Run(RandomTest_OneByte, "Random: 1 byte");
    Run(RandomTest_EightBytes, "Random: 8 bytes");
    Run(RandomTest_OneKilobyte, "Random: 1 KB");
    Run(RandomTest_3319Bytes, "Random: 3319 bytes");

    // =============================================================================
    // Bit Utils Tests
    // =============================================================================
    std::cout << "\n";
    Run(BitUtilsTest_BitsToBytes_Basic, "BitsToBytes: basic (0x01)");
    Run(BitUtilsTest_BitsToBytes_Zero, "BitsToBytes: all zeros");
    Run(BitUtilsTest_BitsToBytes_AllOnes, "BitsToBytes: all ones (0xFF)");
    Run(BitUtilsTest_BytesToBits_Basic, "BytesToBits: basic (0x01)");
    Run(BitUtilsTest_BytesToBits_Zero, "BytesToBits: all zeros");
    Run(BitUtilsTest_BytesToBits_AllOnes, "BytesToBits: all ones (0xFF)");
    Run(BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes, "Roundtrip: BytesToBits --> BitsToBytes");
    Run(BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits, "Roundtrip: BitsToBytes --> BytesToBits");

    // =============================================================================
    // ML-KEM Tests
    // =============================================================================
    std::cout << "\n";
    Run(MlKemTest_Roundtrip_768,             "ML-KEM: roundtrip 768");
    Run(MlKemTest_SharedSecretSize,          "ML-KEM: shared secret = 32 bytes");
    Run(MlKemTest_EncapsulateUniqueness,     "ML-KEM: encap uniqueness");
    Run(MlKemTest_WrongKeyImplicitRejection, "ML-KEM: wrong key implicit reject");

    // =============================================================================
    // ChaCha20-Poly1305 Tests
    // =============================================================================
    std::cout << "\n";
    Run(ChaCha20Test_GenerateKey_Succeeds,    "ChaCha20: key gen succeeds");
    Run(ChaCha20Test_GenerateKey_Unique,      "ChaCha20: key gen unique");
    Run(ChaCha20Test_GenerateNonce_Succeeds,  "ChaCha20: nonce gen succeeds");
    Run(ChaCha20Test_GenerateNonce_Unique,    "ChaCha20: nonce gen unique");

    std::cout << "\n";
    Run(ChaCha20Test_Encrypt_Succeeds,        "ChaCha20: encrypt succeeds");
    Run(ChaCha20Test_Encrypt_CiphertextLength,"ChaCha20: ct len == pt len");
    Run(ChaCha20Test_Encrypt_CiphertextDiffers,"ChaCha20: ct differs from pt");
    Run(ChaCha20Test_Encrypt_EmptyPlaintext,  "ChaCha20: empty pt -> nullopt");
    Run(ChaCha20Test_Encrypt_Deterministic,   "ChaCha20: deterministic");
    Run(ChaCha20Test_Encrypt_DifferentNonce,  "ChaCha20: diff nonce -> diff ct");
    Run(ChaCha20Test_Encrypt_DifferentKey,    "ChaCha20: diff key -> diff ct");

    std::cout << "\n";
    Run(ChaCha20Test_Roundtrip_Basic,         "ChaCha20: roundtrip basic");
    Run(ChaCha20Test_Roundtrip_WithAAD,       "ChaCha20: roundtrip with AAD");
    Run(ChaCha20Test_Roundtrip_4KB,           "ChaCha20: roundtrip 4 KB");
    Run(ChaCha20Test_Roundtrip_4MB,           "ChaCha20: roundtrip 4 MB");
    //Run(ChaCha20Test_Roundtrip_1GB,           "ChaCha20: roundtrip 1 GB"); // This can take over 2 seconds to execute
    Run(ChaCha20Test_Roundtrip_SingleByte,    "ChaCha20: roundtrip 1 byte");
    Run(ChaCha20Test_Decrypt_EmptyCiphertext, "ChaCha20: empty ct -> nullopt");

    std::cout << "\n";
    Run(ChaCha20Test_Auth_WrongKey,           "ChaCha20: wrong key -> reject");
    Run(ChaCha20Test_Auth_WrongNonce,         "ChaCha20: wrong nonce -> reject");
    Run(ChaCha20Test_Auth_TamperedCiphertext, "ChaCha20: tampered ct -> reject");
    Run(ChaCha20Test_Auth_TamperedTag,        "ChaCha20: tampered tag -> reject");
    Run(ChaCha20Test_Auth_WrongAAD,           "ChaCha20: wrong AAD -> reject");
    Run(ChaCha20Test_Auth_MissingAAD,         "ChaCha20: missing AAD -> reject");
    Run(ChaCha20Test_Auth_SpuriousAAD,        "ChaCha20: spurious AAD -> reject");

<<<<<<< Updated upstream
=======
    // =============================================================================
    // SipHash Tests
    // =============================================================================
    std::cout << "\n";
    Run(SipHashTest_BlankKey_BlankInput,   "SipHash: blank key, blank input");
    Run(SipHashTest_BlankKey_NormalInput,  "SipHash: blank key, normal input");
    Run(SipHashTest_NormalKey_BlankInput,  "SipHash: normal key, blank input");
    Run(SipHashTest_NormalKey_NormalInput, "SipHash: normal key, normal input");
    Run(SipHashTest_NormalKey_LargeInput,  "SipHash: normal key, large input");

    // =============================================================================
    // HKDF Tests
    // =============================================================================
    std::cout << "\n";
    Run(HkdfTest_Extract_OutputSize,                        "HKDF: extract output size");
    Run(HkdfTest_Extract_NotEmpty,                          "HKDF: extract not empty");
    Run(HkdfTest_Expand_OutputSize,                         "HKDF: expand output size");
    Run(HkdfTest_DeriveKey_OutputSize,                      "HKDF: derive key output size");
    Run(HkdfTest_DeriveKey_Deterministic,                   "HKDF: derive key deterministic");
    Run(HkdfTest_DeriveKey_DifferentSalt,                   "HKDF: diff salt -> diff output");
    Run(HkdfTest_DeriveKey_DifferentIKM,                    "HKDF: diff ikm -> diff output");
    Run(HkdfTest_Roundtrip_ExtractExpand_MatchesDeriveKey,  "HKDF: extract+expand == derivekey");

    // =============================================================================
    // X25519 Tests
    // =============================================================================
    std::cout << "\n";
    Run(X25519Test_GenerateKeyPair_Succeeds,                  "X25519: keygen succeeds");
    Run(X25519Test_GenerateKeyPair_PublicDiffersFromPrivate,  "X25519: pub != priv");
    Run(X25519Test_GenerateKeyPair_UniquePrivateKeys,         "X25519: unique private keys");
    Run(X25519Test_GenerateKeyPair_UniquePublicKeys,          "X25519: unique public keys");
    Run(X25519Test_GenerateKeyPair_PrivateKeySize,            "X25519: private key = 32 bytes");
    Run(X25519Test_GenerateKeyPair_PublicKeySize,             "X25519: public key = 32 bytes");

    std::cout << "\n";
    Run(X25519Test_PublicKeyFromPrivate_MatchesKeyPair,       "X25519: pub from priv matches");
    Run(X25519Test_PublicKeyFromPrivate_Deterministic,        "X25519: pub from priv deterministic");
    Run(X25519Test_PublicKeyFromPrivate_UniquePerPrivateKey,  "X25519: unique pub per priv");

    std::cout << "\n";
    Run(X25519Test_DeriveSharedSecret_Succeeds,                    "X25519: derive succeeds");
    Run(X25519Test_DeriveSharedSecret_Size,                        "X25519: secret = 32 bytes");
    Run(X25519Test_DeriveSharedSecret_Commutative,                 "X25519: ECDH commutative");
    Run(X25519Test_DeriveSharedSecret_DiffersFromPublicKeys,       "X25519: secret != pub keys");
    Run(X25519Test_DeriveSharedSecret_Deterministic,               "X25519: derive deterministic");
    Run(X25519Test_DeriveSharedSecret_DifferentPeerGivesDifferentSecret, "X25519: diff peer -> diff secret");
    Run(X25519Test_DeriveSharedSecret_WrongPrivateKey,             "X25519: wrong priv -> diff secret");
    Run(X25519Test_DeriveSharedSecret_ThreePartyIndependent,       "X25519: 3-party independent");

    // =============================================================================
    // UDP Socket Tests
    // =============================================================================

    std::cout << "\n";
    Run(UDPSocketTest_OpenClose,           "UDPSocket: open and close");
    Run(UDPSocketTest_Bind,                "UDPSocket: bind ephemeral port");
    Run(UDPSocketTest_SendToReceiveFrom,   "UDPSocket: send and receive");
    Run(UDPSocketTest_Loopback_SenderInfo, "UDPSocket: loopback sender info");
    Run(UDPSocketTest_Loopback_1KB,        "UDPSocket: loopback 1 KB");
    Run(UDPSocketTest_ExternalDNSQuery,    "UDPSocket: 8.8.8.8:53 DNS query");
>>>>>>> Stashed changes

    // =============================================================================
    // Future Tests
    // =============================================================================

    //std::cout << std::endl;
      
    // =============================================================================
    // Test Summary
    // =============================================================================
    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Total:  " << total_tests  << "\n";
    std::cout << GREEN << "Passed: " << passed_tests << RESET << "\n";
    std::cout << RED   << "Failed: " << failed_tests << RESET << "\n\n";
}

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result) {
    if (result == expected) {
        return true;
    } else {
        std::cout << "\n" << RED << "  Expected: " << RESET << expected << "\n";
        std::cout         << RED << "  Got:      " << RESET << result   << "\n";
        return false;
    }
}