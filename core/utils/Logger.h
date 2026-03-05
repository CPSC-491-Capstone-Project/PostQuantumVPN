#pragma once
#include "LogEvent.h"
#include <fstream>
#include <mutex>

class Logger {
public:

    Logger(std::string filename) {
        logFile.open(filename);
    }

    // Writes a log event to the file in a thread safe manner
    void log(LogLevel level, std::string message) {
        LogEvent event(level, message);

        mtx.lock();

        std::string timeStr = ctime(&event.timestamp);
        if (!timeStr.empty())
            timeStr.pop_back();

        logFile << "[" << logLevelToString(event.level) << "] "
                << "[" << timeStr << "] "
                << event.message << "\n";

        logFile.flush();

        mtx.unlock();
    }

private:
    std::ofstream logFile;
    std::mutex    mtx; // Prevents concurrent writes from multiple threads
};