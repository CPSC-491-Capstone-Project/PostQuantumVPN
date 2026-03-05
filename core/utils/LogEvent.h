#pragma once
#include "LogLevel.h"
#include <ctime>

// Represents a single log event with a level, timestamp and message
struct LogEvent {
    LogLevel    level;
    time_t      timestamp;
    std::string message;

    LogEvent(LogLevel lvl, std::string msg) {
        level     = lvl;
        timestamp = time(0);
        message   = msg;
    }

    // Higher level takes priority, ties broken by earliest timestamp
    bool operator<(const LogEvent& other) const {
        if (level != other.level)
            return level < other.level;
        return timestamp > other.timestamp;
    }
};