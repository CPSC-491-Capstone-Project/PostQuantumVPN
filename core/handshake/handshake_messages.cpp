#include "handshake_messages.hpp"
#include "handshake_constants.hpp"

#include <cstring>

namespace core::handshake {

// ============================================================
// Endianness helpers (little-endian)
// ============================================================

static void WriteU32LE(std::uint8_t* buf, std::uint32_t val) {
    buf[0] = static_cast<std::uint8_t>(val);
    buf[1] = static_cast<std::uint8_t>(val >> 8);
    buf[2] = static_cast<std::uint8_t>(val >> 16);
    buf[3] = static_cast<std::uint8_t>(val >> 24);
}

static std::uint32_t ReadU32LE(const std::uint8_t* buf) {
    return static_cast<std::uint32_t>(buf[0])        |
           (static_cast<std::uint32_t>(buf[1]) << 8)  |
           (static_cast<std::uint32_t>(buf[2]) << 16) |
           (static_cast<std::uint32_t>(buf[3]) << 24);
}

static void WriteU64LE(std::uint8_t* buf, std::uint64_t val) {
    for (int i = 0; i < 8; ++i)
        buf[i] = static_cast<std::uint8_t>(val >> (8 * i));
}

static std::uint64_t ReadU64LE(const std::uint8_t* buf) {
    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i)
        val |= (static_cast<std::uint64_t>(buf[i]) << (8 * i));
    return val;
}

// ============================================================
// TYPE 1: INITIATION
// ============================================================
//
// Wire layout (3620 bytes):
//   [0..3]    type        (uint32 LE) = 1
//   [4..7]    sender_index (uint32 LE)
//   [8..39]   ephemeral_x25519          (32)
//   [40..1223] ephemeral_mlkem_ek       (1184)
//   [1224..2311] kem_ciphertext_es      (1088)
//   [2312..2359] encrypted_static_x25519 (48)
//   [2360..3559] encrypted_static_mlkem (1200)
//   [3560..3587] encrypted_timestamp    (28)
//   [3588..3603] mac1                   (16)
//   [3604..3619] mac2                   (16)

std::vector<std::uint8_t> SerializeInitiation(const InitiationMsg& msg) {
    std::vector<std::uint8_t> buf(kInitiationSize, 0);

    WriteU32LE(&buf[0], static_cast<std::uint32_t>(MessageType::Initiation));
    WriteU32LE(&buf[4], msg.sender_index);

    std::memcpy(&buf[8],    msg.ephemeral_x25519.data(),     32);
    std::memcpy(&buf[40],   msg.ephemeral_mlkem_ek.data(),   1184);
    std::memcpy(&buf[1224], msg.kem_ciphertext_es.data(),    1088);
    std::memcpy(&buf[2312], msg.encrypted_static_x25519.data(), 48);
    std::memcpy(&buf[2360], msg.encrypted_static_mlkem.data(),  1200);
    std::memcpy(&buf[3560], msg.encrypted_timestamp.data(),  28);
    std::memcpy(&buf[3588], msg.mac1.data(), 16);
    std::memcpy(&buf[3604], msg.mac2.data(), 16);

    return buf;
}

std::optional<InitiationMsg> DeserializeInitiation(const std::uint8_t* buf, std::size_t len) {
    if (len != kInitiationSize)
        return std::nullopt;

    if (ReadU32LE(&buf[0]) != static_cast<std::uint32_t>(MessageType::Initiation))
        return std::nullopt;

    InitiationMsg msg{};

    msg.sender_index = ReadU32LE(&buf[4]);

    std::memcpy(msg.ephemeral_x25519.data(),        &buf[8],    32);
    std::memcpy(msg.ephemeral_mlkem_ek.data(),      &buf[40],   1184);
    std::memcpy(msg.kem_ciphertext_es.data(),       &buf[1224], 1088);
    std::memcpy(msg.encrypted_static_x25519.data(), &buf[2312], 48);
    std::memcpy(msg.encrypted_static_mlkem.data(),  &buf[2360], 1200);
    std::memcpy(msg.encrypted_timestamp.data(),     &buf[3560], 28);
    std::memcpy(msg.mac1.data(), &buf[3588], 16);
    std::memcpy(msg.mac2.data(), &buf[3604], 16);

    return msg;
}

// ============================================================
// TYPE 2: RESPONSE
// ============================================================
//
// Wire layout (2268 bytes):
//   [0..3]    type            (uint32 LE) = 2
//   [4..7]    sender_index    (uint32 LE)
//   [8..11]   receiver_index  (uint32 LE)
//   [12..43]  ephemeral_x25519          (32)
//   [44..1131] kem_ciphertext_ee        (1088)
//   [1132..2219] kem_ciphertext_se      (1088)
//   [2220..2235] encrypted_empty        (16)
//   [2236..2251] mac1                   (16)
//   [2252..2267] mac2                   (16)

std::vector<std::uint8_t> SerializeResponse(const ResponseMsg& msg) {
    std::vector<std::uint8_t> buf(kResponseSize, 0);

    WriteU32LE(&buf[0], static_cast<std::uint32_t>(MessageType::Response));
    WriteU32LE(&buf[4], msg.sender_index);
    WriteU32LE(&buf[8], msg.receiver_index);

    std::memcpy(&buf[12],   msg.ephemeral_x25519.data(),   32);
    std::memcpy(&buf[44],   msg.kem_ciphertext_ee.data(),  1088);
    std::memcpy(&buf[1132], msg.kem_ciphertext_se.data(),  1088);
    std::memcpy(&buf[2220], msg.encrypted_empty.data(),    16);
    std::memcpy(&buf[2236], msg.mac1.data(), 16);
    std::memcpy(&buf[2252], msg.mac2.data(), 16);

    return buf;
}

std::optional<ResponseMsg> DeserializeResponse(const std::uint8_t* buf, std::size_t len) {
    if (len != kResponseSize)
        return std::nullopt;

    if (ReadU32LE(&buf[0]) != static_cast<std::uint32_t>(MessageType::Response))
        return std::nullopt;

    ResponseMsg msg{};

    msg.sender_index   = ReadU32LE(&buf[4]);
    msg.receiver_index = ReadU32LE(&buf[8]);

    std::memcpy(msg.ephemeral_x25519.data(),  &buf[12],   32);
    std::memcpy(msg.kem_ciphertext_ee.data(), &buf[44],   1088);
    std::memcpy(msg.kem_ciphertext_se.data(), &buf[1132], 1088);
    std::memcpy(msg.encrypted_empty.data(),   &buf[2220], 16);
    std::memcpy(msg.mac1.data(), &buf[2236], 16);
    std::memcpy(msg.mac2.data(), &buf[2252], 16);

    return msg;
}

// ============================================================
// TYPE 3: COOKIE REPLY
// ============================================================
//
// Wire layout (64 bytes):
//   [0..3]   type            (uint32 LE) = 3
//   [4..7]   receiver_index  (uint32 LE)
//   [8..31]  nonce           (24)
//   [32..63] encrypted_cookie (32 = 16 cookie + 16 tag)

std::vector<std::uint8_t> SerializeCookieReply(const CookieReplyMsg& msg) {
    std::vector<std::uint8_t> buf(kCookieReplySize, 0);

    WriteU32LE(&buf[0], static_cast<std::uint32_t>(MessageType::Cookie));
    WriteU32LE(&buf[4], msg.receiver_index);

    std::memcpy(&buf[8],  msg.nonce.data(),            24);
    std::memcpy(&buf[32], msg.encrypted_cookie.data(), 32);

    return buf;
}

std::optional<CookieReplyMsg> DeserializeCookieReply(const std::uint8_t* buf, std::size_t len) {
    if (len != kCookieReplySize)
        return std::nullopt;

    if (ReadU32LE(&buf[0]) != static_cast<std::uint32_t>(MessageType::Cookie))
        return std::nullopt;

    CookieReplyMsg msg{};

    msg.receiver_index = ReadU32LE(&buf[4]);

    std::memcpy(msg.nonce.data(),            &buf[8],  24);
    std::memcpy(msg.encrypted_cookie.data(), &buf[32], 32);

    return msg;
}

// ============================================================
// TYPE 4: TRANSPORT DATA
// ============================================================
//
// Wire layout (variable):
//   [0..3]   type            (uint32 LE) = 4
//   [4..7]   receiver_index  (uint32 LE)
//   [8..15]  counter         (uint64 LE)
//   [16..]   encrypted_payload (includes 16-byte Poly1305 tag)

std::vector<std::uint8_t> SerializeTransport(const TransportDataMsg& msg) {
    const std::size_t total = kTransportHeaderSize + msg.encrypted_payload.size();
    std::vector<std::uint8_t> buf(total, 0);

    WriteU32LE(&buf[0], static_cast<std::uint32_t>(MessageType::Transport));
    WriteU32LE(&buf[4], msg.receiver_index);
    WriteU64LE(&buf[8], msg.counter);

    if (!msg.encrypted_payload.empty())
        std::memcpy(&buf[16], msg.encrypted_payload.data(), msg.encrypted_payload.size());

    return buf;
}

std::optional<TransportDataMsg> DeserializeTransport(const std::uint8_t* buf, std::size_t len) {
    if (len < kTransportHeaderSize)
        return std::nullopt;

    if (ReadU32LE(&buf[0]) != static_cast<std::uint32_t>(MessageType::Transport))
        return std::nullopt;

    const std::size_t payload_size = len - kTransportHeaderSize;
    if (payload_size < 16) // must at least contain Poly1305 tag
        return std::nullopt;

    TransportDataMsg msg{};

    msg.receiver_index = ReadU32LE(&buf[4]);
    msg.counter        = ReadU64LE(&buf[8]);

    msg.encrypted_payload.resize(payload_size);
    std::memcpy(msg.encrypted_payload.data(), &buf[16], payload_size);

    return msg;
}

} // namespace core::handshake
