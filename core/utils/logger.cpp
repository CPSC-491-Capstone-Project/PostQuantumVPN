#include "logger.hpp"
#include <mutex>

namespace core::utils {

    Logger& Logger::getInstance() {
        static Logger instance;
        return instance;
    }

    Logger& Logger::init(const std::string& filename) {
        std::scoped_lock<std::mutex> lock(mutex_);
        if (logFile_.is_open()) {
            logFile_.close();
        }
        logFile_.open(filename);
        stream_ = &logFile_;
        return *this;
    }

    Logger& Logger::init(std::ostream& os) {
        std::scoped_lock<std::mutex> lock(mutex_);
        if (logFile_.is_open()) {
            logFile_.close();
        }
        stream_ = &os;
        return *this;
    }

    Logger& Logger::log(LogLevel level, const std::string& message) {
        // Only log if the event is at or more severe than the threshold
        if (level > threshold_) {
            return *this;
        }
        
        LogEvent event(level, message);
        std::scoped_lock<std::mutex> lock(mutex_);

        *stream_ << event.toString() << "\n";
        stream_->flush();

        return *this;
    }

    Logger& Logger::setLogLevel(LogLevel level) {
        threshold_ = level;
        return *this;
    }


} // namespace core::utils