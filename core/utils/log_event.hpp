#ifndef _PQVPN_CORE_UTILS_LOG_EVENT_HPP_
#define _PQVPN_CORE_UTILS_LOG_EVENT_HPP_

#include "log_level.hpp"

#include <chrono>
#include <string>
#include <compare>

namespace core::utils {

    using TimeStamp = std::chrono::system_clock::time_point;

    // Represents a single log event with a level, timestamp and message
    struct LogEvent {
        LogLevel level_;
        TimeStamp timestamp_;
        std::string message_;

        explicit LogEvent(LogLevel level, const std::string& message)
            : level_{level}
            , timestamp_{std::chrono::system_clock::now()}
            , message_{message}
        {
        }

        constexpr std::strong_ordering operator<=>(const LogEvent& other) const noexcept {
            if (auto cmp = level_ <=> other.level_; cmp != std::strong_ordering::equal) {
                return cmp;
            }
            return timestamp_ <=> other.timestamp_;
        }

        constexpr bool operator==(const LogEvent& other) const noexcept {
            return level_ == other.level_ && timestamp_ == other.timestamp_;
        }


        std::string toString() const {
            auto time_t_val = std::chrono::system_clock::to_time_t(timestamp_);
            std::ostringstream oss;
            oss << "[" << logLevelToString(level_) << "] "
                << "[" << std::put_time(std::localtime(&time_t_val), "%Y-%m-%d %H:%M:%S") << "] "
                << message_;
            return oss.str();
        }
    };
} // namespace core::utils 



#endif // _PQVPN_CORE_UTILS_LOG_EVENT_HPP_