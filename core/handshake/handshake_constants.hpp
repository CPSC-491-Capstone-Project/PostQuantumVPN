#ifndef _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_
#define _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_

#include "blake3.hpp"

#include <string_view>
#include <chrono>

namespace core::handshake {

// ---------------------------------------------------------------------------
// Protocol construction & identifier strings
// ---------------------------------------------------------------------------
// The construction string uniquely identifies this hybrid Noise protocol.
// It MUST differs from WireGuard's "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
inline constexpr std::string_view kConstruction = "Noise_IKpsk2_25519+MLKEM768_ChaChaPoly_BLAKE3";
inline constexpr std::string_view kIdentifier = "PQVPN v1 cmanlove1234@outlook.com";
 
// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------
 
// Initiator begins a new handshake after a session has been active this long.
inline constexpr auto kRekeyAfterTime = std::chrono::seconds{120};
 
// Hard session expiry — both sides drop the session unconditionally.
inline constexpr auto kRejectAfterTime = std::chrono::seconds{180};
 
// Retransmission interval for unanswered handshake initiations.
inline constexpr auto kRekeyTimeout = std::chrono::seconds{5};
 
// Maximum random jitter added to the retransmit timer.
inline constexpr auto kRekeyTimeoutJitterMax = std::chrono::milliseconds{334};
 
// Total wall-clock time before giving up on a handshake attempt.
inline constexpr auto kRekeyAttemptTime = std::chrono::seconds{90};
 
// Maximum retransmission attempts (90 s / 5 s).
inline constexpr std::uint32_t kMaxTimerHandshakes = 18;
 
// Passive keepalive interval.
inline constexpr auto kKeepaliveTimeout = std::chrono::seconds{10};
 
// Server-side cookie secret rotation interval.
inline constexpr auto kCookieRefreshTime = std::chrono::seconds{120};
 
// Minimum interval between consuming handshake initiations from the same peer.
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
// MAC label strings
// ---------------------------------------------------------------------------
 
// Concatenated with responder's static public key to derive the mac1 key.
inline constexpr std::string_view kLabelMac1 = "mac1----";
 
// Concatenated with responder's static public key to derive the cookie encryption key.
inline constexpr std::string_view kLabelCookie = "cookie--";

}

#endif // _PQVPN_CORE_HANDSHAKE_CONSTANTS_HPP_