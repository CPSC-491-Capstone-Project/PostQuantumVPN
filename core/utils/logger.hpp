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

        static void Emergency(const std::string& msg) { getInstance().log(LogLevel::EMERGENCY, msg); }
        static void Alert(const std::string& msg)     { getInstance().log(LogLevel::ALERT, msg); }
        static void Critical(const std::string& msg)  { getInstance().log(LogLevel::CRITICAL, msg); }
        static void Error(const std::string& msg)     { getInstance().log(LogLevel::ERROR, msg); }
        static void Warning(const std::string& msg)   { getInstance().log(LogLevel::WARNING, msg); }
        static void Notice(const std::string& msg)    { getInstance().log(LogLevel::NOTICE, msg); }
        static void Info(const std::string& msg)      { getInstance().log(LogLevel::INFO, msg); }
        static void Debug(const std::string& msg)     { getInstance().log(LogLevel::DEBUG, msg); }


    private:

        Logger() = default;

        std::ofstream logFile_;
        std::ostream* stream_{nullptr};
        std::mutex mutex_; // Prevents concurrent writes from multiple threads
        LogLevel threshold_{LogLevel::DEBUG}; // Default : log everything
    };
} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_LOGGER_HPP_