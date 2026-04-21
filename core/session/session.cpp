#include "session.hpp"
#include "bit_utils.hpp"
#include "handshake_constants.hpp"
#include "logger.hpp"

#include <cstring>
#include <string>

using core::utils::Logger;

namespace core::session {

auto Session::CounterToNonce(std::uint64_t counter)
    -> core::cryptography::chacha20_poly1305::Nonce {
    // WireGuard nonce layout: bytes 0-3 = zero, bytes 4-11 = counter LE
    core::cryptography::chacha20_poly1305::Nonce nonce{};
    core::utils::store64_le(nonce.data() + 4, counter);
    return nonce;
}

auto Session::Seal(ConstByteSpan plaintext)
    -> std::optional<std::vector<std::uint8_t>> {
    namespace cc = core::cryptography::chacha20_poly1305;

    const std::uint64_t counter = send_nonce.fetch_add(1, std::memory_order_relaxed);

    if (counter >= core::handshake::kRejectAfterMessages) {
        Logger::Error("Session::Seal: counter exhausted sender_index=" +
                      std::to_string(sender_index));
        return std::nullopt;
    }

    const auto nonce = CounterToNonce(counter);
    auto enc = cc::Encrypt(plaintext, send_key, nonce);
    if (!enc) {
        Logger::Error("Session::Seal: encryption failed sender_index=" +
                      std::to_string(sender_index));
        return std::nullopt;
    }

    std::vector<std::uint8_t> out;
    out.reserve(enc->ciphertext.size() + enc->tag.size());
    out.insert(out.end(), enc->ciphertext.begin(), enc->ciphertext.end());
    out.insert(out.end(), enc->tag.begin(), enc->tag.end());

    last_sent_time = std::chrono::steady_clock::now();
    return out;
}

auto Session::Open(std::uint64_t counter, ConstByteSpan ciphertext_with_tag)
    -> std::optional<std::vector<std::uint8_t>> {
    namespace cc = core::cryptography::chacha20_poly1305;

    if (counter >= core::handshake::kRejectAfterMessages) {
        Logger::Warning("Session::Open: counter exceeds limit sender_index=" +
                        std::to_string(sender_index));
        return std::nullopt;
    }

    if (!replay_window.Check(counter)) {
        Logger::Warning("Session::Open: replay detected counter=" +
                        std::to_string(counter) + " sender_index=" +
                        std::to_string(sender_index));
        return std::nullopt;
    }

    if (ciphertext_with_tag.size() < cc::kTagBytes) {
        Logger::Warning("Session::Open: payload too short sender_index=" +
                        std::to_string(sender_index));
        return std::nullopt;
    }

    const std::size_t ct_len = ciphertext_with_tag.size() - cc::kTagBytes;
    const ConstByteSpan ciphertext = ciphertext_with_tag.subspan(0, ct_len);

    cc::Tag tag;
    std::memcpy(tag.data(), ciphertext_with_tag.data() + ct_len, cc::kTagBytes);

    const auto nonce = CounterToNonce(counter);
    auto plaintext = cc::Decrypt(ciphertext, tag, recv_key, nonce);

    if (!plaintext) {
        Logger::Warning("Session::Open: authentication failed counter=" +
                        std::to_string(counter) + " sender_index=" +
                        std::to_string(sender_index));
        return std::nullopt;
    }

    replay_window.Accept(counter);
    last_received_time = std::chrono::steady_clock::now();
    return plaintext;
}

bool Session::IsExpired() const {
    return (std::chrono::system_clock::now() - created) > core::handshake::kRejectAfterTime;
}

bool Session::NeedsRekey() const {
    if (rekey_requested.load(std::memory_order_relaxed)) return false;
    if ((std::chrono::system_clock::now() - created) > (core::handshake::kRekeyAfterTime + rekey_jitter))
        return true;
    if (send_nonce.load(std::memory_order_relaxed) >= core::handshake::kRekeyAfterMessages)
        return true;
    return false;
}

bool Session::ShouldSendKeepalive() const {
    if (last_received_time == std::chrono::steady_clock::time_point{}) return false;
    return (std::chrono::steady_clock::now() - last_sent_time) > core::handshake::kKeepaliveTimeout;
}

std::optional<std::vector<std::uint8_t>> Session::CreateKeepalive() {
    return Seal(ConstByteSpan{});
}

} // namespace core::session
