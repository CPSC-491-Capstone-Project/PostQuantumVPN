#ifndef _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_
#define _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_

#include <string>

namespace core::utils {
    // Priority levels for log events
    enum class LogLevel {
        DEBUG = 0,
        INFO  = 1,
        WARN  = 2,
        ERROR = 3
    };

    std::string logLevelToString(LogLevel level) {
        if (level == LogLevel::DEBUG) return "DEBUG";
        if (level == LogLevel::INFO)  return "INFO";
        if (level == LogLevel::WARN)  return "WARN";
        if (level == LogLevel::ERROR) return "ERROR";
        return "UNKNOWN";
    }
} // namespace core::utils


#endif // _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_