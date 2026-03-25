#ifndef _PQVPN_CORE_UTILS_TAI64N_HPP_
#define _PQVPN_CORE_UTILS_TAI64N_HPP_

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace core::utils {
class Tai64n {
public:
    static constexpr std::size_t kSize = 12;
    static constexpr std::uint64_t kTai64Label = 0x4000000000000000ULL;

    using Stamp = std::array<std::byte, kSize>;
    using seconds = std::chrono::seconds;
    using nano_seconds = std::chrono::nanoseconds;

    [[nodiscard]] Stamp Now() {
        auto now = std::chrono::system_clock::now();
        auto since_epoch = now.time_since_epoch();

        auto secs = std::chrono::duration_cast<seconds>(since_epoch);
        auto nanos = std::chrono::duration_cast<nano_seconds>(since_epoch - secs);

        std::uint64_t tai_secs = kTai64Label + static_cast<std::uint64_t>(secs.count());
        std::uint32_t tai_nanos = static_cast<std::uint32_t>(nanos.count());

        Stamp stamp = Encode(tai_secs, tai_nanos);

        std::scoped_lock lock{mutex_};
        if (!IsGreater(stamp, last_)) {
            auto [prev_secs, prev_nanos] = Decode(last_);

            if (prev_nanos < 999'999'999U) {
                stamp = Encode(prev_secs, prev_nanos + 1);
            } else {
                stamp = Encode(prev_secs + 1, 0);
            }
        }

        last_ = stamp;
        return stamp;
    }

    [[nodiscard]] static constexpr bool IsGreater(const Stamp& a, const Stamp& b) {
        for (std::size_t i{0uz}; i < kSize; ++i) {
            if (a[i] != b[i]) {
                return a[i] > b[i];
            }
        }
        return false;
    }

    [[nodiscard]] static constexpr Stamp Encode(std::uint64_t tai_secs, std::uint32_t nanos) {
        Stamp output{};

        output[0]  = static_cast<std::byte>(tai_secs >> 56);
        output[1]  = static_cast<std::byte>(tai_secs >> 48);
        output[2]  = static_cast<std::byte>(tai_secs >> 40);
        output[3]  = static_cast<std::byte>(tai_secs >> 32);
        output[4]  = static_cast<std::byte>(tai_secs >> 24);
        output[5]  = static_cast<std::byte>(tai_secs >> 16);
        output[6]  = static_cast<std::byte>(tai_secs >>  8);
        output[7]  = static_cast<std::byte>(tai_secs);
        output[8]  = static_cast<std::byte>(nanos >> 24);
        output[9]  = static_cast<std::byte>(nanos >> 16);
        output[10] = static_cast<std::byte>(nanos >>  8);
        output[11] = static_cast<std::byte>(nanos);

        return output;
    }

    [[nodiscard]] static constexpr std::pair<std::uint64_t, std::uint32_t> Decode(const Stamp& s) {
        std::uint64_t secs =
            (static_cast<std::uint64_t>(s[0])  << 56) |
            (static_cast<std::uint64_t>(s[1])  << 48) |
            (static_cast<std::uint64_t>(s[2])  << 40) |
            (static_cast<std::uint64_t>(s[3])  << 32) |
            (static_cast<std::uint64_t>(s[4])  << 24) |
            (static_cast<std::uint64_t>(s[5])  << 16) |
            (static_cast<std::uint64_t>(s[6])  <<  8) |
            (static_cast<std::uint64_t>(s[7]));
 
        std::uint32_t nanos =
            (static_cast<std::uint32_t>(s[8])  << 24) |
            (static_cast<std::uint32_t>(s[9])  << 16) |
            (static_cast<std::uint32_t>(s[10]) <<  8) |
            (static_cast<std::uint32_t>(s[11]));

        return {secs, nanos};
    }

private:
    std::mutex mutex_;
    Stamp last_{};

};

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_TAI64N_HPP_