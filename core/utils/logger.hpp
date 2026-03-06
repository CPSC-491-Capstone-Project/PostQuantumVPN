#ifndef _PQVPN_CORE_UTILS_LOGGER_HPP_
#define _PQVPN_CORE_UTILS_LOGGER_HPP_

#include "log_event.hpp"
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>


namespace core::utils {

    class Logger {
    public:
        // Singleton Design Pattern
        Logger(const Logger&) = delete;
        Logger(Logger&&) = delete;
        Logger& operator=(const Logger&) = delete;
        Logger& operator=(Logger&&) = delete;

        static Logger& getInstance();

        void init(const std::string& filename);
        void init(std::ostream& os);
        void log(LogLevel, const std::string& message);

    private:

        Logger() = default;

        std::ofstream logFile_;
        std::ostream* stream_{nullptr};
        std::mutex mutex_; // Prevents concurrent writes from multiple threads
    };
} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_LOGGER_HPP_