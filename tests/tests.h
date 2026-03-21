#ifndef CPP_TEMPLATE_TESTS_H_
#define CPP_TEMPLATE_TESTS_H_

#include <string_view>
#include <iostream>

// =============================================================================
// Logger Tests
// =============================================================================
bool LoggerTest_SingleMessage();
bool LoggerTest_AllLevels();
bool LoggerTest_TimestampPresent();
bool LoggerTest_MultipleMessages();
bool LoggerTest_MT_AllEventsWritten();
bool LoggerTest_MT_NoGarbledLines();
bool LoggerTest_SetLevel_FiltersBelowThreshold();
bool LoggerTest_SetLevel_AllowsAtThreshold();
bool LoggerTest_SetLevel_EmergencyOnly();
bool LoggerTest_SetLevel_DebugLogsEverything();
bool LoggerTest_SetLevel_ChangesMidStream();
bool LoggerTest_LogEvent_SeverityOrdering();
bool LoggerTest_LogEvent_TimestampBreaksTie();

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
// Hex Helpers Tests
// =============================================================================
bool HexTest_Uint8();
bool HexTest_Uint16();
bool HexTest_Uint32();
bool HexTest_Uint64();
bool HexTest_Span_Empty();
bool HexTest_Span_SingleByte();
bool HexTest_Span_MultiByte();
bool HexTest_Vector_Empty();
bool HexTest_Vector_SingleByte();
bool HexTest_Vector_MultiByte();
bool HexTest_Array();

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
bool ChaCha20Test_GenerateKey_Succeeds();
bool ChaCha20Test_GenerateKey_Unique();
bool ChaCha20Test_GenerateNonce_Succeeds();
bool ChaCha20Test_GenerateNonce_Unique();
bool ChaCha20Test_Encrypt_Succeeds();
bool ChaCha20Test_Encrypt_CiphertextLength();
bool ChaCha20Test_Encrypt_CiphertextDiffers();
bool ChaCha20Test_Encrypt_EmptyPlaintext();
bool ChaCha20Test_Encrypt_Deterministic();
bool ChaCha20Test_Encrypt_DifferentNonce();
bool ChaCha20Test_Encrypt_DifferentKey();
bool ChaCha20Test_Roundtrip_Basic();
bool ChaCha20Test_Roundtrip_WithAAD();
bool ChaCha20Test_Roundtrip_4KB();
bool ChaCha20Test_Roundtrip_4MB();
bool ChaCha20Test_Roundtrip_1GB();
bool ChaCha20Test_Roundtrip_SingleByte();
bool ChaCha20Test_Decrypt_EmptyCiphertext();
bool ChaCha20Test_Auth_WrongKey();
bool ChaCha20Test_Auth_WrongNonce();
bool ChaCha20Test_Auth_TamperedCiphertext();
bool ChaCha20Test_Auth_TamperedTag();
bool ChaCha20Test_Auth_WrongAAD();
bool ChaCha20Test_Auth_MissingAAD();
bool ChaCha20Test_Auth_SpuriousAAD();

// =============================================================================
// SipHash Tests
// =============================================================================
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
// BLAKE3 Tests
// =============================================================================
bool Blake3Test_Hash256_Succeeds();
bool Blake3Test_Hash256_OutputSize();
bool Blake3Test_Hash256_EmptyInput();
bool Blake3Test_Hash256_Deterministic();
bool Blake3Test_Hash256_DifferentInputs();
bool Blake3Test_Hash256_DiffersFromInput();
bool Blake3Test_Hash256_SingleByte();
bool Blake3Test_Hash256_1MB();
bool Blake3Test_Hash256_AvalancheEffect();
bool Blake3Test_Hash256_KnownAnswer_Abc();
bool Blake3Test_HashXof_MatchesHash256AtDefaultLen();
bool Blake3Test_HashXof_OutputSize();
bool Blake3Test_HashXof_ZeroOutputLen();
bool Blake3Test_HashXof_EmptyInput();
bool Blake3Test_HashXof_Deterministic();
bool Blake3Test_HashXof_PrefixConsistency();

// =============================================================================
// Event Poller Tests
// =============================================================================
bool EventPollerTest_FullLifecycle();
bool EventPollerTest_TwoPollersAndMoveSemantics();

// =============================================================================
// Future Test Categories
// =============================================================================



// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result);

#endif  // CPP_TEMPLATE_TESTS_H_