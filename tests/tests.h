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
// SipHash Tests
// =============================================================================

// SipHash-2-4 correctness
bool SipHashTest_BlankKey_BlankInput();
bool SipHashTest_BlankKey_NormalInput();
bool SipHashTest_NormalKey_BlankInput();
bool SipHashTest_NormalKey_NormalInput();
bool SipHashTest_NormalKey_LargeInput();

// =============================================================================
// Future Test Categories
// =============================================================================

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result);

#endif  // CPP_TEMPLATE_TESTS_H_