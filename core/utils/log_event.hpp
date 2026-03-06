#ifndef _PQVPN_CORE_UTILS_LOG_EVENT_HPP_
#define _PQVPN_CORE_UTILS_LOG_EVENT_HPP_

#include "log_level.hpp"
#include <chrono>
#include <string>

namespace core::utils {
    // Represents a single log event with a level, timestamp and message
    struct LogEvent {
        LogLevel                                  level;
        std::chrono::system_clock::time_point     timestamp;
        std::string                               message;

        LogEvent(LogLevel lvl, std::string msg) {
            level     = lvl;
            timestamp = std::chrono::system_clock::now();
            message   = msg;
        }

        // Higher level takes priority, ties broken by earliest timestamp
        bool operator<(const LogEvent& other) const {
            if (level != other.level)
                return level < other.level;
            return timestamp > other.timestamp;
        }
    };
} // namespace core::utils 



#endif // _PQVPN_CORE_UTILS_LOG_EVENT_HPP_