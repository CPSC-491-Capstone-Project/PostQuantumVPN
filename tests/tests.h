#ifndef CPP_TEMPLATE_TESTS_H_
#define CPP_TEMPLATE_TESTS_H_

#include <string_view>
#include <iostream>


// =============================================================================
// Random Tests
// =============================================================================

bool RandomTest_SingletonInit();
bool RandomTest_ZeroBytes();
bool RandomTest_OneByte();
bool RandomTest_EightBytes();
bool RandomTest_OneKilobyte();
bool RandomTest_3319Bytes();

// =============================================================================
// Bit Utils Tests
// =============================================================================
bool BitUtilsTest_BitsToBytes_Basic();
bool BitUtilsTest_BitsToBytes_Zero();
bool BitUtilsTest_BitsToBytes_AllOnes();
bool BitUtilsTest_BytesToBits_Basic();
bool BitUtilsTest_BytesToBits_Zero();
bool BitUtilsTest_BytesToBits_AllOnes();
bool BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits();
bool BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes();

// =============================================================================
// ML-KEM (Kyber) Tests
// =============================================================================
bool MlKemTest_Roundtrip_768();
bool MlKemTest_SharedSecretSize();
bool MlKemTest_EncapsulateUniqueness();
bool MlKemTest_WrongKeyImplicitRejection();


// =============================================================================
// ChaCha20-Poly1305 Tests
// =============================================================================

// Key / Nonce generation
bool ChaCha20Test_GenerateKey_Succeeds();
bool ChaCha20Test_GenerateKey_Unique();
bool ChaCha20Test_GenerateNonce_Succeeds();
bool ChaCha20Test_GenerateNonce_Unique();

// Encrypt
bool ChaCha20Test_Encrypt_Succeeds();
bool ChaCha20Test_Encrypt_CiphertextLength();
bool ChaCha20Test_Encrypt_CiphertextDiffers();
bool ChaCha20Test_Encrypt_EmptyPlaintext();
bool ChaCha20Test_Encrypt_Deterministic();
bool ChaCha20Test_Encrypt_DifferentNonce();
bool ChaCha20Test_Encrypt_DifferentKey();

// Decrypt / Roundtrip
bool ChaCha20Test_Roundtrip_Basic();
bool ChaCha20Test_Roundtrip_WithAAD();
bool ChaCha20Test_Roundtrip_4KB();
bool ChaCha20Test_Roundtrip_4MB();
bool ChaCha20Test_Roundtrip_1GB();
bool ChaCha20Test_Roundtrip_SingleByte();
bool ChaCha20Test_Decrypt_EmptyCiphertext();

// Authentication failure
bool ChaCha20Test_Auth_WrongKey();
bool ChaCha20Test_Auth_WrongNonce();
bool ChaCha20Test_Auth_TamperedCiphertext();
bool ChaCha20Test_Auth_TamperedTag();
bool ChaCha20Test_Auth_WrongAAD();
bool ChaCha20Test_Auth_MissingAAD();
bool ChaCha20Test_Auth_SpuriousAAD();

// =============================================================================
<<<<<<< Updated upstream
=======
// SipHash Tests
// =============================================================================

// SipHash-2-4 correctness
bool SipHashTest_BlankKey_BlankInput();
bool SipHashTest_BlankKey_NormalInput();
bool SipHashTest_NormalKey_BlankInput();
bool SipHashTest_NormalKey_NormalInput();
bool SipHashTest_NormalKey_LargeInput();

// =============================================================================
// HKDF Tests
// =============================================================================
bool HkdfTest_Extract_OutputSize();
bool HkdfTest_Extract_NotEmpty();
bool HkdfTest_Expand_OutputSize();
bool HkdfTest_DeriveKey_OutputSize();
bool HkdfTest_DeriveKey_Deterministic();
bool HkdfTest_DeriveKey_DifferentSalt();
bool HkdfTest_DeriveKey_DifferentIKM();
bool HkdfTest_Roundtrip_ExtractExpand_MatchesDeriveKey();

// =============================================================================
// X25519 Tests
// =============================================================================
bool X25519Test_GenerateKeyPair_Succeeds();
bool X25519Test_GenerateKeyPair_PublicDiffersFromPrivate();
bool X25519Test_GenerateKeyPair_UniquePrivateKeys();
bool X25519Test_GenerateKeyPair_UniquePublicKeys();
bool X25519Test_GenerateKeyPair_PrivateKeySize();
bool X25519Test_GenerateKeyPair_PublicKeySize();
bool X25519Test_PublicKeyFromPrivate_MatchesKeyPair();
bool X25519Test_PublicKeyFromPrivate_Deterministic();
bool X25519Test_PublicKeyFromPrivate_UniquePerPrivateKey();
bool X25519Test_DeriveSharedSecret_Succeeds();
bool X25519Test_DeriveSharedSecret_Size();
bool X25519Test_DeriveSharedSecret_Commutative();
bool X25519Test_DeriveSharedSecret_DiffersFromPublicKeys();
bool X25519Test_DeriveSharedSecret_Deterministic();
bool X25519Test_DeriveSharedSecret_DifferentPeerGivesDifferentSecret();
bool X25519Test_DeriveSharedSecret_WrongPrivateKey();
bool X25519Test_DeriveSharedSecret_ThreePartyIndependent();

// =============================================================================
// UDP Socket Tests
// =============================================================================

bool UDPSocketTest_OpenClose();
bool UDPSocketTest_Bind();
bool UDPSocketTest_SendToReceiveFrom();
bool UDPSocketTest_Loopback_SenderInfo();
bool UDPSocketTest_Loopback_1KB();
bool UDPSocketTest_ExternalDNSQuery();

// =============================================================================
>>>>>>> Stashed changes
// Future Test Categories
// =============================================================================

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result);

#endif  // CPP_TEMPLATE_TESTS_H_