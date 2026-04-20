#include "replay_window.hpp"

namespace core::session {

bool ReplayWindow::Check(std::uint64_t counter) const {
    if (counter > last_) return true;
    if (counter + kWindowSize <= last_) return false;
    return !bitmap_[last_ - counter];
}

void ReplayWindow::Accept(std::uint64_t counter) {
    if (counter > last_) {
        bitmap_ <<= static_cast<std::size_t>(counter - last_);
        last_ = counter;
        bitmap_[0] = 1;
    } else {
        bitmap_[last_ - counter] = 1;
    }
}

} // namespace core::session
