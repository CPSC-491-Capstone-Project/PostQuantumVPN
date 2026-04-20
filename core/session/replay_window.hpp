#ifndef _PQVPN_CORE_SESSION_REPLAY_WINDOW_HPP_
#define _PQVPN_CORE_SESSION_REPLAY_WINDOW_HPP_

#include <bitset>
#include <cstdint>

namespace core::session {

// Sliding-window replay filter for inbound packet counters.
// Prevents retransmit attacks by rejecting duplicate or out-of-window counters.
//
// Thread safety: assumes single-threaded access from the receive loop.
// If concurrent Open() calls are added later, wrap Check+Accept in a mutex.
class ReplayWindow {
public:
    static constexpr std::size_t kWindowSize = 2048;

    // Returns true if counter is acceptable (not a replay and not too old).
    [[nodiscard]] bool Check(std::uint64_t counter) const;

    // Marks counter as seen. Must only be called after successful decryption.
    void Accept(std::uint64_t counter);

private:
    std::uint64_t last_{0};
    std::bitset<kWindowSize> bitmap_{};
};

} // namespace core::session

#endif // _PQVPN_CORE_SESSION_REPLAY_WINDOW_HPP_
