// =============================================================================
// Test Runner
//
// This is the ONLY .cpp file in the tests/ directory. All test
// implementations live in their own .hpp files and are #included here,
// forming a single translation unit.
//
// Adding a new test module:
//   1. Create tests/<module>_tests.hpp with your test functions.
//   2. #include it below (keep the list alphabetical).
//   3. Call Run(...) in main() with the new test functions.
// =============================================================================

#include "test_utils.hpp"   // forward decl of test_helper; included first so
                            // all test headers below can see it

// --- Test module headers (alphabetical) ---
#include "bit_utils_tests.hpp"
#include "blake3_tests.hpp"
#include "chacha20_poly1305_tests.hpp"
#include "event_poller_tests.hpp"
#include "derive_session_keys_tests.hpp"
#include "handshake_helper_tests.hpp"
#include "handshake_initiation_tests.hpp"
#include "handshake_response_tests.hpp"
#include "handshake_timer_tests.hpp"
#include "hex_helpers_tests.hpp"
#include "hkdf_tests.hpp"
#include "ipv4_tests.hpp"
#include "logger_tests.hpp"
#include "ml_kem_tests.hpp"
#include "random_tests.hpp"
#include "secure_memory_tests.hpp"
#include "session_manager_tests.hpp"
#include "siphash_tests.hpp"
#include "tai64n_tests.hpp"
#include "tun_device_tests.hpp"
#include "udp_socket_tests.hpp"
#include "x25519_tests.hpp"
#include "index_table_tests.hpp"

// --- Standard headers used by the runner itself ---
#include "handshake_constants.hpp"
#include "logger.hpp"
#include "timer.hpp"
#include "x25519.hpp"

#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>

using core::utils::Logger;

static int total_tests  = 0;
static int passed_tests = 0;
static int failed_tests = 0;

static std::string log_filename;
static std::string_view g_filter = "";

static const char* GREEN = "\033[32m";
static const char* RED   = "\033[31m";
static const char* CYAN  = "\033[36m";
static const char* RESET = "\033[0m";

// =============================================================================
// Run helpers
// =============================================================================
void Run(bool (*test)(), std::string_view name) {
    if (!g_filter.empty() && name.find(g_filter) == std::string_view::npos) return;

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

    // Flush after each test so a crash pinpoints the failing test in real time.
    std::cout << "  " << timer.ElapsedStr() << std::endl;
}

// Overload that lets the test start the timer itself (e.g. after thread setup).
void Run(bool (*test)(std::function<void()>), std::string_view name) {
    if (!g_filter.empty() && name.find(g_filter) == std::string_view::npos) return;

    total_tests++;
    core::utils::Timer timer;

    std::cout << CYAN << "[TEST] " << RESET << std::left << std::setw(40) << name;

    bool result = test([&timer] { timer.Start(); });
    timer.Stop();

    if (result) {
        passed_tests++;
        std::cout << GREEN << "[PASS]" << RESET;
    } else {
        failed_tests++;
        std::cout << RED   << "[FAIL]" << RESET;
    }

    std::cout << "  " << timer.ElapsedStr() << std::endl;
}

// =============================================================================
// Logger helpers
// =============================================================================
static std::string MakeLogFilename() {
    auto now = std::chrono::system_clock::now();
    auto time_t_val = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "Test_Log_"
        << std::put_time(std::localtime(&time_t_val), "%Y%m%d_%H%M%S")
        << ".log";
    return oss.str();
}

static void InitLoggerToFile() {
    Logger::getInstance().init(log_filename);
    Logger::getInstance().setLogLevel(core::utils::LogLevel::DEBUG);
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {

    if (argc >= 2) g_filter = argv[1];

    log_filename = MakeLogFilename();
    InitLoggerToFile();

    std::cout << "========================================\n";
    std::cout << "Running Test Suite\n";
    std::cout << "========================================\n";

    // =============================================================================
    // Logger Tests
    // =============================================================================
    // std::cout << "\n";
    // Run(LoggerTest_SingleMessage,      "Logger: single message");
    // Run(LoggerTest_AllLevels,          "Logger: all levels");
    // Run(LoggerTest_TimestampPresent,   "Logger: timestamp present");
    // Run(LoggerTest_MultipleMessages,   "Logger: multiple messages");
    // Run(LoggerTest_MT_AllEventsWritten,"Logger: MT all events written");
    // Run(LoggerTest_MT_NoGarbledLines,  "Logger: MT no garbled lines");
    // Run(LoggerTest_SetLevel_FiltersBelowThreshold,  "Logger: setLevel filters below");
    // Run(LoggerTest_SetLevel_AllowsAtThreshold,       "Logger: setLevel allows at/above");
    // Run(LoggerTest_SetLevel_EmergencyOnly,           "Logger: emergency-only mode");
    // Run(LoggerTest_SetLevel_DebugLogsEverything,     "Logger: debug logs everything");
    // Run(LoggerTest_SetLevel_ChangesMidStream,        "Logger: level change mid-stream");
    // Run(LoggerTest_LogEvent_SeverityOrdering,        "LogEvent: severity ordering");
    // Run(LoggerTest_LogEvent_TimestampBreaksTie,      "LogEvent: timestamp tiebreak");

    // // Reset the logger after running the Logger tests
    // // so that all other tests will output to the correct file
    // InitLoggerToFile();

    // // =============================================================================
    // // Random Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(RandomTest_SingletonInit, "Random: Init");
    // Run(RandomTest_ZeroBytes,     "Random: 0 bytes");
    // Run(RandomTest_OneByte,       "Random: 1 byte");
    // Run(RandomTest_EightBytes,    "Random: 8 bytes");
    // Run(RandomTest_OneKilobyte,   "Random: 1 KB");
    // Run(RandomTest_3319Bytes,     "Random: 3319 bytes");

    // // =============================================================================
    // // Bit Utils Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(BitUtilsTest_BitsToBytes_Basic,   "BitsToBytes: basic (0x01)");
    // Run(BitUtilsTest_BitsToBytes_Zero,    "BitsToBytes: all zeros");
    // Run(BitUtilsTest_BitsToBytes_AllOnes, "BitsToBytes: all ones (0xFF)");
    // Run(BitUtilsTest_BytesToBits_Basic,   "BytesToBits: basic (0x01)");
    // Run(BitUtilsTest_BytesToBits_Zero,    "BytesToBits: all zeros");
    // Run(BitUtilsTest_BytesToBits_AllOnes, "BytesToBits: all ones (0xFF)");
    // Run(BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes, "Roundtrip: BytesToBits --> BitsToBytes");
    // Run(BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits, "Roundtrip: BitsToBytes --> BytesToBits");

    // // =============================================================================
    // // Hex Helpers Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(HexTest_Uint8,             "Hex: uint8_t");
    // Run(HexTest_Uint16,            "Hex: uint16_t");
    // Run(HexTest_Uint32,            "Hex: uint32_t");
    // Run(HexTest_Uint64,            "Hex: uint64_t");
    // Run(HexTest_Span_Empty,        "Hex: span empty");
    // Run(HexTest_Span_SingleByte,   "Hex: span single byte");
    // Run(HexTest_Span_MultiByte,    "Hex: span multi byte");
    // Run(HexTest_Vector_Empty,      "Hex: vector empty");
    // Run(HexTest_Vector_SingleByte, "Hex: vector single byte");
    // Run(HexTest_Vector_MultiByte,  "Hex: vector multi byte");
    // Run(HexTest_Array,             "Hex: std::array");

    // // =============================================================================
    // // ML-KEM Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(MlKemTest_Roundtrip_768,             "ML-KEM: roundtrip 768");
    // Run(MlKemTest_SharedSecretSize,          "ML-KEM: shared secret = 32 bytes");
    // Run(MlKemTest_EncapsulateUniqueness,     "ML-KEM: encap uniqueness");
    // Run(MlKemTest_WrongKeyImplicitRejection, "ML-KEM: wrong key implicit reject");

    // // =============================================================================
    // // ChaCha20-Poly1305 Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(ChaCha20Test_GenerateKey_Succeeds,    "ChaCha20: key gen succeeds");
    // Run(ChaCha20Test_GenerateKey_Unique,      "ChaCha20: key gen unique");
    // Run(ChaCha20Test_GenerateNonce_Succeeds,  "ChaCha20: nonce gen succeeds");
    // Run(ChaCha20Test_GenerateNonce_Unique,    "ChaCha20: nonce gen unique");

    // std::cout << "\n";
    // Run(ChaCha20Test_Encrypt_Succeeds,         "ChaCha20: encrypt succeeds");
    // Run(ChaCha20Test_Encrypt_CiphertextLength, "ChaCha20: ct len == pt len");
    // Run(ChaCha20Test_Encrypt_CiphertextDiffers,"ChaCha20: ct differs from pt");
    // Run(ChaCha20Test_Encrypt_Deterministic,    "ChaCha20: deterministic");
    // Run(ChaCha20Test_Encrypt_DifferentNonce,   "ChaCha20: diff nonce -> diff ct");
    // Run(ChaCha20Test_Encrypt_DifferentKey,     "ChaCha20: diff key -> diff ct");

    // std::cout << "\n";
    // Run(ChaCha20Test_Roundtrip_Basic,          "ChaCha20: roundtrip basic");
    // Run(ChaCha20Test_Roundtrip_WithAAD,        "ChaCha20: roundtrip with AAD");
    // Run(ChaCha20Test_Roundtrip_4KB,            "ChaCha20: roundtrip 4 KB");
    // Run(ChaCha20Test_Roundtrip_4MB,            "ChaCha20: roundtrip 4 MB");
    // //Run(ChaCha20Test_Roundtrip_1GB,          "ChaCha20: roundtrip 1 GB"); // can take >2 s
    // Run(ChaCha20Test_Roundtrip_SingleByte,     "ChaCha20: roundtrip 1 byte");
    // Run(ChaCha20Test_Decrypt_EmptyCiphertext,  "ChaCha20: empty ct -> nullopt");

    // std::cout << "\n";
    // Run(ChaCha20Test_Auth_WrongKey,            "ChaCha20: wrong key -> reject");
    // Run(ChaCha20Test_Auth_WrongNonce,          "ChaCha20: wrong nonce -> reject");
    // Run(ChaCha20Test_Auth_TamperedCiphertext,  "ChaCha20: tampered ct -> reject");
    // Run(ChaCha20Test_Auth_TamperedTag,         "ChaCha20: tampered tag -> reject");
    // Run(ChaCha20Test_Auth_WrongAAD,            "ChaCha20: wrong AAD -> reject");
    // Run(ChaCha20Test_Auth_MissingAAD,          "ChaCha20: missing AAD -> reject");
    // Run(ChaCha20Test_Auth_SpuriousAAD,         "ChaCha20: spurious AAD -> reject");

    // // =============================================================================
    // // Secure Memory Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(CtMemcmpTest_Equal,                      "ct_memcmp: equal arrays");
    // Run(CtMemcmpTest_NotEqual,                   "ct_memcmp: not equal arrays");
    // Run(CtMemcmpTest_SingleByteDifferenceMiddle, "ct_memcmp: diff byte in middle");
    // Run(CtMemcmpTest_DifferenceAtLastByte,       "ct_memcmp: diff at last byte");
    // Run(CtMemcmpTest_DifferenceAtFirstByte,      "ct_memcmp: diff at first byte");
    // Run(CtMemcmpTest_ZeroLength,                 "ct_memcmp: zero length");
    // Run(CtMemcmpTest_SpanOverload_Equal,         "ct_memcmp: span equal");
    // Run(CtMemcmpTest_SpanOverload_DifferentLengths, "ct_memcmp: span diff lengths");
    // Run(SecureZeroTest_ZerosArray,               "secure_zero: zeros array");
    // Run(SecureZeroTest_ZerosRawPointer,          "secure_zero: zeros raw pointer");
    // Run(SecureZeroTest_ZeroLength,               "secure_zero: zero length no-op");

    // // =============================================================================
    // // SipHash Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(SipHashTest_BlankKey_BlankInput,   "SipHash: blank key, blank input");
    // Run(SipHashTest_BlankKey_NormalInput,  "SipHash: blank key, normal input");
    // Run(SipHashTest_NormalKey_BlankInput,  "SipHash: normal key, blank input");
    // Run(SipHashTest_NormalKey_NormalInput, "SipHash: normal key, normal input");
    // Run(SipHashTest_NormalKey_LargeInput,  "SipHash: normal key, large input");

    // // =============================================================================
    // // HKDF Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(HkdfTest_Extract_OutputSize,                       "HKDF: extract output size");
    // Run(HkdfTest_Extract_NotEmpty,                         "HKDF: extract not empty");
    // Run(HkdfTest_Expand_OutputSize,                        "HKDF: expand output size");
    // Run(HkdfTest_DeriveKey_OutputSize,                     "HKDF: derive key output size");
    // Run(HkdfTest_DeriveKey_Deterministic,                  "HKDF: derive key deterministic");
    // Run(HkdfTest_DeriveKey_DifferentSalt,                  "HKDF: diff salt -> diff output");
    // Run(HkdfTest_DeriveKey_DifferentIKM,                   "HKDF: diff ikm -> diff output");
    // Run(HkdfTest_Roundtrip_ExtractExpand_MatchesDeriveKey, "HKDF: extract+expand == derivekey");

    // // =============================================================================
    // // X25519 Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(X25519Test_GenerateKeyPair_Succeeds,               "X25519: keygen succeeds");
    // Run(X25519Test_GenerateKeyPair_PublicDiffersFromPrivate,"X25519: pub != priv");
    // Run(X25519Test_GenerateKeyPair_UniquePrivateKeys,       "X25519: unique private keys");
    // Run(X25519Test_GenerateKeyPair_UniquePublicKeys,        "X25519: unique public keys");
    // Run(X25519Test_GenerateKeyPair_PrivateKeySize,          "X25519: private key = 32 bytes");
    // Run(X25519Test_GenerateKeyPair_PublicKeySize,           "X25519: public key = 32 bytes");

    // std::cout << "\n";
    // Run(X25519Test_PublicKeyFromPrivate_MatchesKeyPair,      "X25519: pub from priv matches");
    // Run(X25519Test_PublicKeyFromPrivate_Deterministic,       "X25519: pub from priv deterministic");
    // Run(X25519Test_PublicKeyFromPrivate_UniquePerPrivateKey, "X25519: unique pub per priv");

    // std::cout << "\n";
    // Run(X25519Test_DeriveSharedSecret_Succeeds,                         "X25519: derive succeeds");
    // Run(X25519Test_DeriveSharedSecret_Size,                             "X25519: secret = 32 bytes");
    // Run(X25519Test_DeriveSharedSecret_Commutative,                      "X25519: ECDH commutative");
    // Run(X25519Test_DeriveSharedSecret_DiffersFromPublicKeys,            "X25519: secret != pub keys");
    // Run(X25519Test_DeriveSharedSecret_Deterministic,                    "X25519: derive deterministic");
    // Run(X25519Test_DeriveSharedSecret_DifferentPeerGivesDifferentSecret,"X25519: diff peer -> diff secret");
    // Run(X25519Test_DeriveSharedSecret_WrongPrivateKey,                  "X25519: wrong priv -> diff secret");
    // Run(X25519Test_DeriveSharedSecret_ThreePartyIndependent,            "X25519: 3-party independent");

    // =============================================================================
    // TunDevice Tests  (requires sudo — tests skip gracefully if not root)
    // =============================================================================
    std::cout << "\n";
    Run(TunDeviceTest_OpenClose,              "TunDevice: open and close");
    Run(TunDeviceTest_OpenAlreadyOpen,        "TunDevice: open already open");
    Run(TunDeviceTest_DoubleClose,            "TunDevice: double close");
    Run(TunDeviceTest_MoveConstruct,          "TunDevice: move construct");
    Run(TunDeviceTest_MoveAssign,             "TunDevice: move assign");
    Run(TunDeviceTest_SetNonBlocking,         "TunDevice: set non-blocking");
    Run(TunDeviceTest_Write_InjectAndReceive, "TunDevice: write inject and receive");
    Run(TunDeviceTest_Read_CaptureOutbound,   "TunDevice: read capture outbound");
    Run(TunDeviceTest_Write_LargePacket,      "TunDevice: write 1400-byte packet");
    Run(TunDeviceTest_EventPoller_Integration,"TunDevice: EventPoller integration");
    Run(TunDeviceTest_OperationsOnClosed,          "TunDevice: ops on closed device");
    Run(TunDeviceTest_BurstInbound,               "TunDevice: burst 100 inbound packets");
    Run(TunDeviceTest_MultiDestinationPorts,      "TunDevice: multi-destination port routing");
    Run(TunDeviceTest_Multithread_ParallelInject, "TunDevice: 4-thread parallel inject");
    Run(TunDeviceTest_Multithread_Bidirectional,  "TunDevice: concurrent bidirectional");

    // =============================================================================
    // UDP Socket Tests
    // =============================================================================
    // std::cout << "\n";
    // Run(UDPSocketTest_OpenClose,           "UDPSocket: open and close");
    // Run(UDPSocketTest_Bind,                "UDPSocket: bind ephemeral port");
    // Run(UDPSocketTest_SendToReceiveFrom,   "UDPSocket: send and receive");
    // Run(UDPSocketTest_Loopback_SenderInfo, "UDPSocket: loopback sender info");
    // Run(UDPSocketTest_Loopback_1KB,        "UDPSocket: loopback 1 KB");
    // //Run(UDPSocketTest_ExternalDNSQuery,  "UDPSocket: 8.8.8.8:53 DNS query"); // blocked on Fullerton network

    // // =============================================================================
    // // IPv4 Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(IPv4Test_DefaultIsZero,           "IPv4: default is 0.0.0.0");
    // Run(IPv4Test_FromOctets,              "IPv4: construct from octets");
    // Run(IPv4Test_FromUint32,              "IPv4: construct from uint32");
    // Run(IPv4Test_FromString_Valid,        "IPv4: construct from string");
    // Run(IPv4Test_FromString_Malformed,    "IPv4: malformed string");
    // Run(IPv4Test_Roundtrip_OctetsToString,"IPv4: octets -> string");
    // Run(IPv4Test_Roundtrip_StringToOctets,"IPv4: string -> octets");
    // Run(IPv4Test_NetworkOrder,            "IPv4: network byte order");
    // Run(IPv4Test_HostNetworkRoundtrip,    "IPv4: host <-> network roundtrip");
    // Run(IPv4Test_Equality,                "IPv4: equality");
    // Run(IPv4Test_Ordering,                "IPv4: ordering");
    // Run(IPv4Test_Constants,               "IPv4: consteval constants");
    // Run(IPv4Test_FullyConstexpr,          "IPv4: fully constexpr chain");

    // // =============================================================================
    // // BLAKE3 Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(Blake3Test_Hash256_Succeeds,          "BLAKE3: hash succeeds");
    // Run(Blake3Test_Hash256_OutputSize,        "BLAKE3: output = 32 bytes");
    // Run(Blake3Test_Hash256_EmptyInput,        "BLAKE3: empty input -> nullopt");
    // Run(Blake3Test_Hash256_Deterministic,     "BLAKE3: deterministic");
    // Run(Blake3Test_Hash256_DifferentInputs,   "BLAKE3: diff inputs -> diff hash");
    // Run(Blake3Test_Hash256_DiffersFromInput,  "BLAKE3: hash != input");
    // Run(Blake3Test_Hash256_SingleByte,        "BLAKE3: single byte input");
    // Run(Blake3Test_Hash256_1MB,               "BLAKE3: 1 MB input");
    // Run(Blake3Test_Hash256_AvalancheEffect,   "BLAKE3: avalanche effect");
    // Run(Blake3Test_Hash256_KnownAnswer_Abc,   "BLAKE3: known answer (abc)");

    // std::cout << "\n";
    // Run(Blake3Test_HashXof_MatchesHash256AtDefaultLen, "BLAKE3 XOF: matches Hash256 at 32B");
    // Run(Blake3Test_HashXof_OutputSize,        "BLAKE3 XOF: correct output size");
    // Run(Blake3Test_HashXof_ZeroOutputLen,     "BLAKE3 XOF: zero len -> nullopt");
    // Run(Blake3Test_HashXof_EmptyInput,        "BLAKE3 XOF: empty input -> nullopt");
    // Run(Blake3Test_HashXof_Deterministic,     "BLAKE3 XOF: deterministic");
    // Run(Blake3Test_HashXof_PrefixConsistency, "BLAKE3 XOF: prefix consistency");

    // // =============================================================================
    // // Event Poller Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(EventPollerTest_FullLifecycle,              "EventPoller: full lifecycle");
    // Run(EventPollerTest_TwoPollersAndMoveSemantics, "EventPoller: two pollers + move");
    // Run(EventPollerTest_OperationsOnClosedPoller,   "EventPoller: ops on closed poller");

    // // =============================================================================
    // // TAI64N Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(Tai64nTest_SingleThread_UniqueTimestamps, "TAI64N: single-thread unique");
    // Run(Tai64nTest_MT_AllUnique,                  "TAI64N: MT all unique (1K/thread)");
    // Run(Tai64nTest_MT_Throughput,                 "TAI64N: MT throughput (100K/thread)");

    // // =============================================================================
    // // Handshake Helpers Tests
    // // =============================================================================
    // core::handshake::InitHandshakeConstants();

    // std::cout << "\n";
    // Run(MixHashTest_SingleByte,                     "MixHash: single byte");
    // Run(MixHashTest_EmptyData,                      "MixHash: empty data");
    // Run(MixHashTest_Deterministic,                  "MixHash: deterministic");
    // Run(MixHashTest_DifferentData,                  "MixHash: diff data -> diff hash");
    // Run(MixHashTest_DifferentStartingHash,          "MixHash: diff start -> diff hash");
    // Run(MixHashTest_OrderMatters,                   "MixHash: order matters");
    // Run(MixHashTest_ConcatVsSequential,             "MixHash: concat != sequential");
    // Run(MixHashTest_KnownAnswer_ZeroHash_Abc,       "MixHash: KAT zeros || abc");
    // Run(MixHashTest_KnownAnswer_ProtocolInitialHash,"MixHash: KAT protocol init hash");
    // Run(MixHashTest_LargeData,                      "MixHash: 4 KB data");

    // std::cout << "\n";
    // Run(KDF1Test_Succeeds,       "KDF1: succeeds");
    // Run(KDF1Test_Deterministic,  "KDF1: deterministic");
    // Run(KDF1Test_DifferentKey,   "KDF1: diff key -> diff output");
    // Run(KDF1Test_DifferentInput, "KDF1: diff input -> diff output");
    // Run(KDF1Test_EmptyInput,     "KDF1: empty input succeeds");
    // Run(KDF1Test_KnownAnswer,    "KDF1: KAT manual computation");

    // std::cout << "\n";
    // Run(KDF2Test_Succeeds_DistinctOutputs, "KDF2: T0 != T1");
    // Run(KDF2Test_Deterministic,            "KDF2: deterministic");
    // Run(KDF2Test_T0MatchesKDF1,            "KDF2: T0 == KDF1 output");
    // Run(KDF2Test_EmptyInput,               "KDF2: empty input succeeds");
    // Run(KDF2Test_DifferentKey,             "KDF2: diff key -> diff output");

    // std::cout << "\n";
    // Run(KDF3Test_Succeeds_DistinctOutputs, "KDF3: T0 != T1 != T2");
    // Run(KDF3Test_Deterministic,            "KDF3: deterministic");
    // Run(KDF3Test_T0T1MatchKDF2,            "KDF3: T0,T1 == KDF2 output");
    // Run(KDF3Test_EmptyInput,               "KDF3: empty input succeeds");
    // Run(KDF3Test_DifferentKey,             "KDF3: diff key -> diff output");

    // std::cout << "\n";
    // Run(EncryptAndHashTest_Roundtrip_Basic,  "EaH: roundtrip basic");
    // Run(EncryptAndHashTest_HashConvergence,  "EaH: hash convergence");
    // Run(EncryptAndHashTest_HashChanges,      "EaH: hash changes after encrypt");
    // Run(EncryptAndHashTest_OutputSize,       "EaH: output = pt + 16 tag");
    // Run(EncryptAndHashTest_EmptyPlaintext,   "EaH: empty pt (encrypted nothing)");
    // Run(EncryptAndHashTest_Deterministic,    "EaH: deterministic");

    // std::cout << "\n";
    // Run(DecryptAndHashTest_TamperedCiphertext,  "DaH: tampered ct -> reject");
    // Run(DecryptAndHashTest_TamperedTag,         "DaH: tampered tag -> reject");
    // Run(DecryptAndHashTest_HashUnchangedOnFailure,"DaH: H unchanged on failure");
    // Run(DecryptAndHashTest_WrongKey,            "DaH: wrong key -> reject");
    // Run(DecryptAndHashTest_InputTooShort,       "DaH: input too short -> reject");
    // Run(DecryptAndHashTest_MismatchedHash,      "DaH: mismatched H -> reject");

    // // =============================================================================
    // // Session Manager Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(SessionManagerTest_ActivateSession_FindableByIndex,    "SessionManager: activate findable by index");
    // Run(SessionManagerTest_ActivateSession_KeysMatch,          "SessionManager: keys match secrets");
    // Run(SessionManagerTest_ActivateSession_ZeroKeyRejected,    "SessionManager: zero key rejected");
    // Run(SessionManagerTest_TransitionSession_OldRemovedNewActive, "SessionManager: transition removes old");
    // Run(SessionManagerTest_TransitionSession_FailureKeepsOldSession, "SessionManager: transition fail keeps old");

    // // =============================================================================
    // // Index Table Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(IndexTableTest_NewIndex_InsertAndLookup,      "IndexTable: new index insert and lookup");
    // Run(IndexTableTest_Lookup_MissingIndex,           "IndexTable: lookup missing index");
    // Run(IndexTableTest_NewIndex_UniqueIndices,        "IndexTable: new index unique");
    // Run(IndexTableTest_SwapHandshakeToKeypair_UpdatesEntry, "IndexTable: swap handshake to keypair");
    // Run(IndexTableTest_Delete_RemovesEntry,           "IndexTable: delete removes entry");

    // // =============================================================================
    // // Handshake Timer Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(HandshakeTimerTest_DeadlineTimer_CallbackFires,          "HandshakeTimer: callback fires");
    // Run(HandshakeTimerTest_DeadlineTimer_DisarmPreventsCallback, "HandshakeTimer: disarm prevents callback");
    // Run(HandshakeTimerTest_DeadlineTimer_RearmRestarts,          "HandshakeTimer: rearm restarts countdown");
    // Run(HandshakeTimerTest_DeadlineTimer_CallbackFiresOnce,      "HandshakeTimer: callback fires once");
    // Run(HandshakeTimerTest_DeadlineTimer_IsArmedReflectsState,   "HandshakeTimer: IsArmed state");
    // Run(HandshakeTimerTest_DeadlineTimer_ConcurrentArmDisarm,    "HandshakeTimer: concurrent arm/disarm");
    // Run(HandshakeTimerTest_Jitter_InRange,                       "HandshakeTimer: jitter in [0, 334ms)");
    // Run(HandshakeTimerTest_Jitter_Varies,                        "HandshakeTimer: jitter varies");

    // std::cout << "\n";
    // Run(HandshakeTimerTest_Retransmit_ArmsOnCall,                "HandshakeTimer 9a: arm on call");
    // Run(HandshakeTimerTest_Retransmit_DisarmResetsAttempts,      "HandshakeTimer 9a: disarm resets attempts");
    // Run(HandshakeTimerTest_Retransmit_CallbackIncrementsAttempts,"HandshakeTimer 9a: callback increments attempts");
    // Run(HandshakeTimerTest_Retransmit_StopsAtMaxAttempts,        "HandshakeTimer 9a: stops at 18 attempts");

    // std::cout << "\n";
    // Run(HandshakeTimerTest_Rekey_FiresImmediately_WhenNonceExceedsMax, "HandshakeTimer 9b: immediate on nonce overflow");
    // Run(HandshakeTimerTest_Rekey_FiresImmediately_WhenKeypairExpired,  "HandshakeTimer 9b: immediate on expired keypair");
    // Run(HandshakeTimerTest_Rekey_ArmedForFutureExpiry,                 "HandshakeTimer 9b: armed for future expiry");
    // Run(HandshakeTimerTest_LastMinute_TrueWhenOldEnough,               "HandshakeTimer 9b: last-minute when old enough");
    // Run(HandshakeTimerTest_LastMinute_FalseWhenFlagSet,                "HandshakeTimer 9b: last-minute blocked by flag");
    // Run(HandshakeTimerTest_LastMinute_FalseWhenTooYoung,               "HandshakeTimer 9b: no last-minute for young keypair");
    // Run(HandshakeTimerTest_Rekey_DisarmClearsSentFlag,                 "HandshakeTimer 9b: disarm clears sent flag");

    // std::cout << "\n";
    // Run(HandshakeTimerTest_KeyExpiry_ArmsOnCall,                 "HandshakeTimer 9c: arms on call");
    // Run(HandshakeTimerTest_KeyExpiry_DisarmsOnCall,              "HandshakeTimer 9c: disarms on call");
    // Run(HandshakeTimerTest_KeyExpiry_ClearAllZerosSlots,         "HandshakeTimer 9c: ClearAll zeros all slots");
    // Run(HandshakeTimerTest_KeyExpiry_CallbackFiresAndZerosKeypairs, "HandshakeTimer 9c: callback zeros keypairs");
    // Run(HandshakeTimerTest_KeyExpiry_DoesNotTouchStaticStatic,   "HandshakeTimer 9c: does not touch static_static");

    // // =============================================================================
    // // Handshake Initiation Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(CreateInitiation_ReturnsMessage,                    "CreateInitiation: returns message");
    // Run(CreateInitiation_MessageSize,                       "CreateInitiation: message is 3620 bytes");
    // Run(CreateInitiation_TypeField,                         "CreateInitiation: type field = 1");
    // Run(CreateInitiation_SenderIndexMatchesState,           "CreateInitiation: sender index matches state");
    // Run(CreateInitiation_StateIsInitiationCreated,          "CreateInitiation: state = InitiationCreated");
    // Run(CreateInitiation_ChainingKeyModified,               "CreateInitiation: chaining key modified");
    // Run(CreateInitiation_HashModified,                      "CreateInitiation: hash modified");
    // Run(CreateInitiation_EphemeralX25519PrivateStored,      "CreateInitiation: X25519 private key stored");
    // Run(CreateInitiation_EphemeralMlKemDkStored,            "CreateInitiation: ML-KEM DK stored");
    // Run(CreateInitiation_EphemeralX25519InMessageMatchesState, "CreateInitiation: X25519 EK in msg matches state");
    // Run(CreateInitiation_EphemeralMlKemEkInMessageMatchesState,"CreateInitiation: ML-KEM EK in msg matches state");
    // Run(CreateInitiation_MacFieldsAreZero,                  "CreateInitiation: MAC fields are zero");
    // Run(CreateInitiation_IndexTableEntryExists,             "CreateInitiation: index table entry exists");
    // Run(CreateInitiation_IndexTableEntryPointsToPeer,       "CreateInitiation: index table entry -> peer");
    // Run(CreateInitiation_LocalIndexNonZero,                 "CreateInitiation: local index != 0");
    // Run(CreateInitiation_EphemeralKeysAreRandom,            "CreateInitiation: ephemeral keys are random");
    // Run(CreateInitiation_MessageDeserializes,               "CreateInitiation: message deserializes");

    // // =============================================================================
    // // ConsumeMessageInitiation Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(ConsumeInitiation_Succeeds,                   "ConsumeInitiation: succeeds");
    // Run(ConsumeInitiation_StateIsInitiationConsumed,  "ConsumeInitiation: state = InitiationConsumed");
    // Run(ConsumeInitiation_ChainingKeyUpdated,         "ConsumeInitiation: chaining key updated");
    // Run(ConsumeInitiation_HashUpdated,                "ConsumeInitiation: hash updated");
    // Run(ConsumeInitiation_RemoteIndexStored,          "ConsumeInitiation: remote index stored");
    // Run(ConsumeInitiation_EphemeralX25519Stored,      "ConsumeInitiation: ephemeral X25519 stored");
    // Run(ConsumeInitiation_EphemeralMlKemEkStored,     "ConsumeInitiation: ephemeral ML-KEM EK stored");
    // Run(ConsumeInitiation_TimestampStored,            "ConsumeInitiation: timestamp stored");
    // Run(ConsumeInitiation_TamperedCiphertext_Rejected,"ConsumeInitiation: tampered ct rejected");
    // Run(ConsumeInitiation_UnknownInitiator_Rejected,  "ConsumeInitiation: unknown initiator rejected");
    // Run(ConsumeInitiation_ReplayRejected,             "ConsumeInitiation: replay rejected");
    // Run(ConsumeInitiation_ChainingKeyConverges,       "ConsumeInitiation: C and H converge");

    // // =============================================================================
    // // CreateMessageResponse Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(CreateResponse_Succeeds,                   "CreateResponse: succeeds");
    // Run(CreateResponse_MessageSize,                "CreateResponse: message is 2268 bytes");
    // Run(CreateResponse_TypeField,                  "CreateResponse: type field = 2");
    // Run(CreateResponse_SenderIndexMatchesState,    "CreateResponse: sender index matches state");
    // Run(CreateResponse_ReceiverIndexMatchesInitiator, "CreateResponse: receiver index = initiator index");
    // Run(CreateResponse_StateIsResponseCreated,     "CreateResponse: state = ResponseCreated");
    // Run(CreateResponse_MacFieldsAreZero,           "CreateResponse: MAC fields are zero");
    // Run(CreateResponse_IndexTableEntryExists,      "CreateResponse: index table entry exists");
    // Run(CreateResponse_WrongState_Rejected,        "CreateResponse: wrong state rejected");
    // Run(CreateResponse_MessageDeserializes,        "CreateResponse: message deserializes");
    // Run(E2E_InitiationAndResponse_ChainingKeyConverges, "E2E: initiation + response C non-trivial");

    // // =============================================================================
    // // ConsumeMessageResponse Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(ConsumeResponse_Succeeds,                      "ConsumeResponse: succeeds");
    // Run(ConsumeResponse_StateIsResponseConsumed,       "ConsumeResponse: state = ResponseConsumed");
    // Run(ConsumeResponse_ChainingKeyUpdated,            "ConsumeResponse: chaining key updated");
    // Run(ConsumeResponse_RemoteIndexStored,             "ConsumeResponse: remote index stored");
    // Run(ConsumeResponse_EphemeralX25519PrivateZeroed,  "ConsumeResponse: ephemeral X25519 priv zeroed");
    // Run(ConsumeResponse_EphemeralMlKemDkZeroed,        "ConsumeResponse: ephemeral ML-KEM DK zeroed");
    // Run(ConsumeResponse_TamperedTag_Rejected,          "ConsumeResponse: tampered tag rejected");
    // Run(ConsumeResponse_WrongState_Rejected,           "ConsumeResponse: wrong state rejected");
    // Run(ConsumeResponse_ReceiverIndexMismatch_Rejected,"ConsumeResponse: receiver index mismatch rejected");
    // Run(E2E_FullHandshake_ChainingKeyConverges,        "E2E: full handshake C and H converge");

    // // =============================================================================
    // // DeriveSessionKeys Tests
    // // =============================================================================
    // std::cout << "\n";
    // Run(DeriveSessionKeys_Succeeds,                          "DeriveSessionKeys: full simulation succeeds");
    // Run(DeriveSessionKeys_Initiator_KeypairInCurrent,        "DeriveSessionKeys: initiator keypair in Current");
    // Run(DeriveSessionKeys_Responder_KeypairInNext,           "DeriveSessionKeys: responder keypair in Next");
    // Run(DeriveSessionKeys_InitiatorSendEqualsResponderReceive,"DeriveSessionKeys: i.send == r.receive");
    // Run(DeriveSessionKeys_InitiatorReceiveEqualsResponderSend,"DeriveSessionKeys: i.receive == r.send");
    // Run(DeriveSessionKeys_KeysAreNonZero,                    "DeriveSessionKeys: keys are non-zero");
    // Run(DeriveSessionKeys_IsInitiatorFlag,                   "DeriveSessionKeys: is_initiator flag");
    // Run(DeriveSessionKeys_IndicesCrossMatch,                 "DeriveSessionKeys: indices cross-match");
    // Run(DeriveSessionKeys_IndexTableSwappedToKeypair,        "DeriveSessionKeys: index table swapped");
    // Run(DeriveSessionKeys_HandshakeStateZeroed,              "DeriveSessionKeys: handshake state zeroed");
    // Run(DeriveSessionKeys_ChainingKeyZeroed,                 "DeriveSessionKeys: chaining key zeroed");
    // Run(DeriveSessionKeys_HashZeroed,                        "DeriveSessionKeys: hash zeroed");
    // Run(DeriveSessionKeys_WrongState_Rejected,               "DeriveSessionKeys: wrong state rejected");
    // Run(DeriveSessionKeys_KeysAreUnique,                     "DeriveSessionKeys: keys are unique per handshake");
    // Run(DeriveSessionKeys_OneServer_FiveClients_Concurrent,  "DeriveSessionKeys: 1 server + 5 clients concurrent");

    // =============================================================================
    // Future Tests
    // =============================================================================

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
// test_helper — defined here; declared in test_utils.hpp
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result) {
    if (result == expected) {
        return true;
    }
    std::cout << "\n" << RED << "  Expected: " << RESET << expected << "\n";
    std::cout         << RED << "  Got:      " << RESET << result   << "\n";
    return false;
}
