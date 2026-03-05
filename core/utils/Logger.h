#ifndef LOGGER_H
#define LOGGER_H

#include "LogEvent.h"
#include <fstream>
#include <mutex>
#include <sstream>
#include <iomanip>

class Logger {
public:

    Logger(std::string filename) {
        logFile.open(filename);
    }

    // Writes a log event to the file in a thread safe manner
    void log(LogLevel level, std::string message) {
        LogEvent event(level, message);

        mtx.lock();

        // Convert chrono time point to readable string
        auto time_t_val = std::chrono::system_clock::to_time_t(event.timestamp);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");

        logFile << "[" << logLevelToString(event.level) << "] "
                << "[" << oss.str() << "] "
                << event.message << "\n";

        logFile.flush();

        mtx.unlock();
    }

private:
    std::ofstream logFile;
    std::mutex    mtx; // Prevents concurrent writes from multiple threads
};

#endif