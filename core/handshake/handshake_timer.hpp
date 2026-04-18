#ifndef _PQVPN_CORE_HANDSHAKE_HANDSHAKE_TIMER_HPP_
#define _PQVPN_CORE_HANDSHAKE_HANDSHAKE_TIMER_HPP_

#include "handshake_constants.hpp"
#include "keypair.hpp"
#include "random.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>

namespace core::handshake {

// Thread-safe single-shot deadline timer.
// Arm() starts (or restarts) the countdown; callback fires on expiry unless Disarm() cancels it.
class DeadlineTimer {
public:
    using Callback = std::function<void()>;
    using Clock    = std::chrono::steady_clock;

    explicit DeadlineTimer(Callback cb)
        : callback_(std::move(cb))
        , thread_(&DeadlineTimer::Loop, this)
    {}

    ~DeadlineTimer() {
        {
            std::lock_guard lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

    void Arm(std::chrono::nanoseconds timeout) {
        {
            std::lock_guard lock(mutex_);
            armed_    = true;
            deadline_ = Clock::now() + timeout;
        }
        cv_.notify_all();
    }

    void Disarm() {
        std::lock_guard lock(mutex_);
        armed_ = false;
    }

    [[nodiscard]] bool IsArmed() const {
        std::lock_guard lock(mutex_);
        return armed_;
    }

    DeadlineTimer(const DeadlineTimer&)            = delete;
    DeadlineTimer& operator=(const DeadlineTimer&) = delete;
    DeadlineTimer(DeadlineTimer&&)                 = delete;
    DeadlineTimer& operator=(DeadlineTimer&&)      = delete;

private:
    void Loop() {
        std::unique_lock lock(mutex_);
        while (!stop_) {
            if (!armed_) {
                cv_.wait(lock, [this] { return armed_ || stop_; });
                continue;
            }
            const auto deadline = deadline_;
            // Returns false on timeout (predicate still false), true if woken early
            const bool woken_early = cv_.wait_until(lock, deadline, [this, &deadline] {
                return stop_ || !armed_ || deadline_ != deadline;
            });
            if (!woken_early && armed_ && deadline_ == deadline) {
                armed_ = false;
                lock.unlock();
                callback_();
                lock.lock();
            }
        }
    }

    Callback                callback_;
    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    bool                    armed_{false};
    bool                    stop_{false};
    Clock::time_point       deadline_{};
    std::thread             thread_;
};

// Uniform random jitter in [0, kRekeyTimeoutJitterMax).
inline std::chrono::milliseconds RetransmitJitter() {
    std::uint32_t r{};
    auto bytes = core::utils::Random::GenerateNRandomBytes(sizeof(r));
    std::memcpy(&r, bytes.data(), sizeof(r));
    const auto max_ms = static_cast<std::uint32_t>(kRekeyTimeoutJitterMax.count());
    return std::chrono::milliseconds{r % max_ms};
}

// Owns the three handshake timers for a single peer.
// Callbacks are injected at construction and wired to handshake logic later.
struct HandshakeTimers {

    // 9a — retransmission
    std::atomic<std::uint32_t> handshake_attempts{0};
    DeadlineTimer              retransmit;

    // Call after CreateMessageInitiation + send.
    void ArmRetransmit() {
        retransmit.Arm(kRekeyTimeout + RetransmitJitter());
    }

    // Call when ConsumeMessageResponse succeeds.
    void DisarmRetransmit() {
        handshake_attempts.store(0, std::memory_order_relaxed);
        retransmit.Disarm();
    }

    // 9b — periodic rekey
    std::atomic<bool> sent_last_minute_handshake{false};
    DeadlineTimer     rekey;

    // Call after sending a transport data packet.
    // Fires immediately if send_nonce already exceeds kRekeyAfterMessages.
    void ArmRekey(std::chrono::system_clock::time_point keypair_created, std::uint64_t send_nonce) {
        using namespace std::chrono;
        if (send_nonce >= kRekeyAfterMessages) {
            rekey.Arm(nanoseconds{0});
            return;
        }
        const auto elapsed   = duration_cast<seconds>(system_clock::now() - keypair_created);
        const auto remaining = kRekeyAfterTime - elapsed;
        rekey.Arm(remaining > seconds{0} ? remaining : nanoseconds{0});
    }

    void DisarmRekey() {
        rekey.Disarm();
        sent_last_minute_handshake.store(false, std::memory_order_relaxed);
    }

    // Returns true when a last-minute handshake is needed on this keypair.
    // Caller is responsible for setting sent_last_minute_handshake after acting.
    [[nodiscard]] bool NeedsLastMinuteHandshake(const Keypair& kp) const {
        using namespace std::chrono;
        // REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT = 165 s
        constexpr auto threshold = kRejectAfterTime - kKeepaliveTimeout - kRekeyTimeout;
        const auto age = duration_cast<seconds>(system_clock::now() - kp.created);
        return age >= threshold && !sent_last_minute_handshake.load(std::memory_order_relaxed);
    }

    // 9c — key expiry / zeroing
    DeadlineTimer key_expiry;

    // Call after DeriveSessionKeys (new keypair created).
    void ArmKeyExpiry() {
        key_expiry.Arm(kRejectAfterTime * 3);
    }

    void DisarmKeyExpiry() {
        key_expiry.Disarm();
    }

    // Callbacks:
    //   on_retransmit_expired — increment handshake_attempts; re-initiate or clear peer state
    //   on_rekey_expired      — call CreateMessageInitiation (initiator-side only)
    //   on_key_expiry_expired — zero keypairs + handshake state (not precomputed_static_static)
    HandshakeTimers(
        std::function<void()> on_retransmit_expired,
        std::function<void()> on_rekey_expired,
        std::function<void()> on_key_expiry_expired
    )
        : retransmit(std::move(on_retransmit_expired))
        , rekey(std::move(on_rekey_expired))
        , key_expiry(std::move(on_key_expiry_expired))
    {}

    HandshakeTimers(const HandshakeTimers&)            = delete;
    HandshakeTimers& operator=(const HandshakeTimers&) = delete;
    HandshakeTimers(HandshakeTimers&&)                 = delete;
    HandshakeTimers& operator=(HandshakeTimers&&)      = delete;
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_HANDSHAKE_TIMER_HPP_
