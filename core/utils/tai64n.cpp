#include "tai64n.hpp"

#include <span>

namespace core::utils {

Tai64nStamp::Tai64nStamp(std::uint64_t seconds, std::uint32_t nanoseconds) 
    : data_{
        static_cast<std::uint8_t>(seconds >> 56),
        static_cast<std::uint8_t>(seconds >> 48),
        static_cast<std::uint8_t>(seconds >> 40),
        static_cast<std::uint8_t>(seconds >> 32),
        static_cast<std::uint8_t>(seconds >> 24),
        static_cast<std::uint8_t>(seconds >> 16),
        static_cast<std::uint8_t>(seconds >>  8),
        static_cast<std::uint8_t>(seconds),
        static_cast<std::uint8_t>(nanoseconds >> 24),
        static_cast<std::uint8_t>(nanoseconds >> 16),
        static_cast<std::uint8_t>(nanoseconds >>  8),
        static_cast<std::uint8_t>(nanoseconds)
    } {}

constexpr Tai64nStamp& Tai64nStamp::operator++() {
    auto nanos = Nanoseconds();

    if (nanos < 999'999'999U) {
        ++nanos;
        data_[8]  = static_cast<std::uint8_t>(nanos >> 24);
        data_[9]  = static_cast<std::uint8_t>(nanos >> 16);
        data_[10] = static_cast<std::uint8_t>(nanos >>  8);
        data_[11] = static_cast<std::uint8_t>(nanos);
    } else {
        data_[8]  = 0;
        data_[9]  = 0;
        data_[10] = 0;
        data_[11] = 0;

        for (auto i{7uz}; ; --i) {
            if (++data_[i] != 0) break;
            if (i == 0uz) break;
        }
    }

    return *this;
}

std::uint64_t Tai64nStamp::Hash() const {
    return Fnv1a(ConstByteSpan{data_.data(), kSize});
}

constexpr std::uint64_t Tai64nStamp::Seconds() const {
    return (static_cast<std::uint64_t>(data_[0]) << 56) |
           (static_cast<std::uint64_t>(data_[1]) << 48) |
           (static_cast<std::uint64_t>(data_[2]) << 40) |
           (static_cast<std::uint64_t>(data_[3]) << 32) |
           (static_cast<std::uint64_t>(data_[4]) << 24) |
           (static_cast<std::uint64_t>(data_[5]) << 16) |
           (static_cast<std::uint64_t>(data_[6]) <<  8) |
           (static_cast<std::uint64_t>(data_[7]));
}

constexpr std::uint32_t Tai64nStamp::Nanoseconds() const {
    return (static_cast<std::uint32_t>(data_[8])  << 24) |
           (static_cast<std::uint32_t>(data_[9])  << 16) |
           (static_cast<std::uint32_t>(data_[10]) <<  8) |
           (static_cast<std::uint32_t>(data_[11]));
}

// ============================================================================
// Tai64n
// ============================================================================
Tai64nStamp Tai64n::Now() {
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();

    auto secs = std::chrono::duration_cast<seconds>(since_epoch);
    auto nanos = std::chrono::duration_cast<nano_seconds>(since_epoch - secs);

    std::uint64_t tai_secs = kTai64Label + static_cast<std::uint64_t>(secs.count());
    std::uint32_t tai_nanos = static_cast<std::uint32_t>(nanos.count());

    Tai64nStamp stamp(tai_secs, tai_nanos);

    std::scoped_lock lock{mutex_};

    if (stamp <= last_) {
        stamp = last_;
        ++stamp;
    }

    last_ = stamp;
    return stamp;
}

} // namespace core::utils