#ifndef _PQVPN_CORE_HANDSHAKE_MESSAGES_HPP_
#define _PQVPN_CORE_HANDSHAKE_MESSAGES_HPP_

#include "handshake_constants.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace core::handshake {

// ============================================================
// Message size constants
// ============================================================

constexpr std::size_t kInitiationSize     = 3620;
constexpr std::size_t kResponseSize       = 2268;
constexpr std::size_t kCookieReplySize    = 64;
constexpr std::size_t kTransportHeaderSize = 16;

// ============================================================
// TYPE 1: INITIATION (3620 bytes)
// ============================================================

struct InitiationMsg {
    std::uint32_t sender_index{0};

    std::array<std::uint8_t, 32>   ephemeral_x25519{};
    std::array<std::uint8_t, 1184> ephemeral_mlkem_ek{};
    std::array<std::uint8_t, 1088> kem_ciphertext_es{};

    std::array<std::uint8_t, 48>   encrypted_static_x25519{};
    std::array<std::uint8_t, 1200> encrypted_static_mlkem{};
    std::array<std::uint8_t, 28>   encrypted_timestamp{};

    std::array<std::uint8_t, 16>   mac1{};
    std::array<std::uint8_t, 16>   mac2{};
};

[[nodiscard]] std::vector<std::uint8_t> SerializeInitiation(const InitiationMsg& msg);
[[nodiscard]] std::optional<InitiationMsg> DeserializeInitiation(const std::uint8_t* buf, std::size_t len);

// ============================================================
// TYPE 2: RESPONSE (2268 bytes)
// ============================================================

struct ResponseMsg {
    std::uint32_t sender_index{0};
    std::uint32_t receiver_index{0};

    std::array<std::uint8_t, 32>   ephemeral_x25519{};
    std::array<std::uint8_t, 1088> kem_ciphertext_ee{};
    std::array<std::uint8_t, 1088> kem_ciphertext_se{};

    std::array<std::uint8_t, 16>   encrypted_empty{};

    std::array<std::uint8_t, 16>   mac1{};
    std::array<std::uint8_t, 16>   mac2{};
};

[[nodiscard]] std::vector<std::uint8_t> SerializeResponse(const ResponseMsg& msg);
[[nodiscard]] std::optional<ResponseMsg> DeserializeResponse(const std::uint8_t* buf, std::size_t len);

// ============================================================
// TYPE 3: COOKIE REPLY (64 bytes)
// ============================================================

struct CookieReplyMsg {
    std::uint32_t receiver_index{0};
    std::array<std::uint8_t, 24> nonce{};
    std::array<std::uint8_t, 32> encrypted_cookie{}; // 16 cookie + 16 tag
};

[[nodiscard]] std::vector<std::uint8_t> SerializeCookieReply(const CookieReplyMsg& msg);
[[nodiscard]] std::optional<CookieReplyMsg> DeserializeCookieReply(const std::uint8_t* buf, std::size_t len);

// ============================================================
// TYPE 4: TRANSPORT DATA (variable size)
// ============================================================

struct TransportDataMsg {
    std::uint32_t receiver_index{0};
    std::uint64_t counter{0};
    std::vector<std::uint8_t> encrypted_payload{}; // includes Poly1305 tag
};

[[nodiscard]] std::vector<std::uint8_t> SerializeTransport(const TransportDataMsg& msg);
[[nodiscard]] std::optional<TransportDataMsg> DeserializeTransport(const std::uint8_t* buf, std::size_t len);

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_MESSAGES_HPP_
