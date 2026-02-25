#ifndef _PQVPN_CORE_UTILS_TIMER_HPP_
#define _PQVPN_CORE_UTILS_TIMER_HPP_

#include <chrono>
#include <string>
#include <string_view>
#include <iostream>

namespace core::utils {

    class Timer {
    public:
        using Clock = std::chrono::steady_clock;
        using TimePoint = Clock::time_point;
        using Duration = std::chrono::nanoseconds;

        void Start() {
            start_ = Clock::now();
        }

        void Stop() {
            end_= Clock::now();
        }

        [[nodiscard]] Duration Elapsed() const {
            return std::chrono::duration_cast<Duration>(end_- start_);
        }

        [[nodiscard]] std::string ElapsedStr() const {
            auto ns = Elapsed().count();
            if (ns < 1'000LL) 
                return std::to_string(ns) + " ns";
            if (ns < 1'000'000LL)
                return std::to_string(static_cast<double>(ns) / 1'000.0) + " us";
            if (ns < 1'000'000'000LL)
                return std::to_string(static_cast<double>(ns) / 1'000'000.0) + " ms";
            return std::to_string(static_cast<double>(ns) / 1'000'000'000.0) + " s";
        }

    private:
        TimePoint start_{};
        TimePoint end_{};

    };

} // namespace core:utils

#endif // _PQVPN_CORE_UTILS_TIMER_HPP_