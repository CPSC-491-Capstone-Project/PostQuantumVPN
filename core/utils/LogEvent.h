#ifndef LOGEVENT_H
#define LOGEVENT_H

#include "LogLevel.h"
#include <chrono>
#include <string>

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

#endif