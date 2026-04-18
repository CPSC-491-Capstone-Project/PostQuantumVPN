#ifndef _PQVPN_CORE_HANDSHAKE_KEYPAIR_HPP_
#define _PQVPN_CORE_HANDSHAKE_KEYPAIR_HPP_

#include "chacha20_poly1305.hpp"
#include "secure_memory.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

namespace core::handshake {

// Forward declaration - replay filter defined by session module
struct ReplayFilter;

struct Keypair {
    // Encryption keys
    core::cryptography::chacha20_poly1305::Key send_key{};
    core::cryptography::chacha20_poly1305::Key receive_key{};

    // Atomic nonce incremented per outgoing packet, must never wrap
    std::atomic<std::uint64_t> send_nonce{0};

    // Placeholder for session module's sliding window replay filter
    ReplayFilter* replay_filter{nullptr};

    bool is_initiator{false};

    std::chrono::system_clock::time_point created{};

    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};

    // Zeros send and receive keys before destruction
    void Clear() {
        core::utils::secure_zero(send_key);
        core::utils::secure_zero(receive_key);
    }

    ~Keypair() { Clear(); }
};

// Manages the three keypair slots for graceful rekeying transitions
class KeypairManager {
public:

    // Promotes next to current and demotes current to previous
    // Called when responder decrypts first transport packet using next keypair
    void PromoteNext() {
        std::lock_guard<std::mutex> lock(mutex_);

        if (previous_) {
            previous_->Clear();
        }

        previous_ = std::move(current_);
        current_  = std::move(next_);
        next_     = nullptr;
    }

    // Initiator path - places new keypair directly into current
    void SetCurrent(std::unique_ptr<Keypair> keypair) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (previous_) {
            previous_->Clear();
        }

        previous_ = std::move(current_);
        current_  = std::move(keypair);
    }

    void SetNext(std::unique_ptr<Keypair> keypair) {
        std::lock_guard<std::mutex> lock(mutex_);
        next_ = std::move(keypair);
    }

    Keypair* Current() {
        std::lock_guard<std::mutex> lock(mutex_);
        return current_.get();
    }

    Keypair* Previous() {
        std::lock_guard<std::mutex> lock(mutex_);
        return previous_.get();
    }

    Keypair* Next() {
        std::lock_guard<std::mutex> lock(mutex_);
        return next_.get();
    }

    // Zeros and destroys all three keypair slots. Called by key expiry timer.
    void ClearAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (current_)  { current_->Clear();  current_.reset(); }
        if (previous_) { previous_->Clear(); previous_.reset(); }
        if (next_)     { next_->Clear();     next_.reset(); }
    }

private:
    std::unique_ptr<Keypair> current_{nullptr};
    std::unique_ptr<Keypair> previous_{nullptr};
    std::unique_ptr<Keypair> next_{nullptr};
    std::mutex mutex_;
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_KEYPAIR_HPP_