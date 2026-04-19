#ifndef _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_
#define _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_

#include <string>

namespace core::utils {
    // Priority levels for log events
    enum class LogLevel {
        EMERGENCY = 0,  // System unusable
        ALERT     = 1,  // Immediate action required
        CRITICAL  = 2,  // Critical failure
        ERROR     = 3,  // Operation failed
        WARNING   = 4,  // Unexpected but not failed
        NOTICE    = 5,  // Normal but significant
        INFO      = 6,  // Routine operational
        DEBUG     = 7   // Verbose troubleshooting
    };

    inline std::string logLevelToString(LogLevel level) {
        switch (level) {
            case LogLevel::EMERGENCY: return "EMERGENCY";
            case LogLevel::ALERT:     return "ALERT";
            case LogLevel::CRITICAL:  return "CRITICAL";
            case LogLevel::ERROR:     return "ERROR";
            case LogLevel::WARNING:   return "WARNING";
            case LogLevel::NOTICE:    return "NOTICE";
            case LogLevel::INFO:      return "INFO";
            case LogLevel::DEBUG:     return "DEBUG";
        }
        return "UNKNOWN";
    }
} // namespace core::utils


#endif // _PQVPN_CORE_UTILS_LOG_LEVEL_HPP_