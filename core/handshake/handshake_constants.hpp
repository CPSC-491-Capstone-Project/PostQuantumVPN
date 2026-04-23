#ifndef _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_
#define _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_

#include "bit_utils.hpp"
#include "blake3.hpp"

#include <string_view>
#include <chrono>

namespace core::handshake {

using ByteSpan      = core::utils::ByteSpan;
using ConstByteSpan = core::utils::ConstByteSpan;
using Blake3Hash    = std::array<std::uint8_t, BLAKE3_OUT_LEN>;

// ---------------------------------------------------------------------------
// Protocol construction & identifier strings
// ---------------------------------------------------------------------------
// The construction string uniquely identifies this hybrid Noise protocol.
// It MUST differs from WireGuard's "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
inline constexpr std::string_view kConstruction = "Noise_IKpsk2_25519+MLKEM768_ChaChaPoly_BLAKE3";
inline constexpr std::string_view kIdentifier = "PQVPN v1 cmanlove1234@outlook.com";

// ---------------------------------------------------------------------------
// Precomputed protocol constants (computed once at startup)
// ---------------------------------------------------------------------------
const Blake3Hash& InitialChainingKey();
const Blake3Hash& InitialHash();

// Must be called once during startup
// Safe to call unlimited times
void InitHandshakeConstants();

// ---------------------------------------------------------------------------
// Handshake message types
// ---------------------------------------------------------------------------
enum class MessageType : std::uint8_t {
    Initiation = 1,
    Response   = 2,
    Cookie     = 3,
    Transport  = 4
};
 
// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------
 
inline constexpr auto kRekeyAfterTime = std::chrono::seconds{120};
inline constexpr auto kRejectAfterTime = std::chrono::seconds{180};
inline constexpr auto kRekeyTimeout = std::chrono::seconds{5};
inline constexpr auto kRekeyTimeoutJitterMax = std::chrono::milliseconds{334};
inline constexpr auto kRekeyAttemptTime = std::chrono::seconds{90};
inline constexpr std::uint32_t kMaxTimerHandshakes = 18;
inline constexpr auto kKeepaliveTimeout = std::chrono::seconds{10};
inline constexpr auto kCookieRefreshTime = std::chrono::seconds{120};
inline constexpr auto kHandshakeInitiationRate = std::chrono::milliseconds{20};

// ---------------------------------------------------------------------------
// Message counter limits
// ---------------------------------------------------------------------------
 
// Re-handshake after sending this many transport data messages.
inline constexpr std::uint64_t kRekeyAfterMessages = std::uint64_t{1} << 60;
 
// Absolute maximum — never encrypt more than this many messages under one key.
// 2^64 - 2^13 - 1
inline constexpr std::uint64_t kRejectAfterMessages = UINT64_MAX - (std::uint64_t{1} << 13);
 
// ---------------------------------------------------------------------------
// ML-KEM key size constants
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMlKemDecapsulationKeyBytes = 2400; // dk (ML-KEM-768)
inline constexpr std::size_t kMlKemEncapsulationKeyBytes = 1184; // ek (ML-KEM-768)

// ---------------------------------------------------------------------------
// MAC label strings
// ---------------------------------------------------------------------------
 
// Concatenated with responder's static public key to derive the mac1 key.
inline constexpr std::string_view kLabelMac1 = "mac1----";
 
// Concatenated with responder's static public key to derive the cookie encryption key.
inline constexpr std::string_view kLabelCookie = "cookie--";

}

#endif // _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_