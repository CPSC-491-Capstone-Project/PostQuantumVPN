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

        Logger& init(const std::string& filename);
        Logger& init(std::ostream& os);
        Logger& log(LogLevel, const std::string& message);
        Logger& setLogLevel(LogLevel level);

        static Logger& Emergency(const std::string& msg) { return getInstance().log(LogLevel::EMERGENCY, msg); }
        static Logger& Alert(const std::string& msg)     { return getInstance().log(LogLevel::ALERT, msg); }
        static Logger& Critical(const std::string& msg)  { return getInstance().log(LogLevel::CRITICAL, msg); }
        static Logger& Error(const std::string& msg)     { return getInstance().log(LogLevel::ERROR, msg); }
        static Logger& Warning(const std::string& msg)   { return getInstance().log(LogLevel::WARNING, msg); }
        static Logger& Notice(const std::string& msg)    { return getInstance().log(LogLevel::NOTICE, msg); }
        static Logger& Info(const std::string& msg)      { return getInstance().log(LogLevel::INFO, msg); }
        static Logger& Debug(const std::string& msg)     { return getInstance().log(LogLevel::DEBUG, msg); }


    private:

        Logger() = default;

        std::ofstream logFile_;
        std::ostream* stream_{nullptr};
        std::mutex mutex_; // Prevents concurrent writes from multiple threads
        LogLevel threshold_{LogLevel::DEBUG}; // Default : log everything
    };
} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_LOGGER_HPP_