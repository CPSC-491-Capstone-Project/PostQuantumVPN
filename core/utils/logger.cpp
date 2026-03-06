#include "logger.hpp"
#include <mutex>

namespace core::utils {

    Logger& Logger::getInstance() {
        static Logger instance;
        return instance;
    }

    void Logger::init(const std::string& filename) {
        std::scoped_lock<std::mutex> lock(mutex_);
        logFile_.open(filename);
        stream_ = &logFile_;
    }

    void Logger::init(std::ostream& os) {
        std::scoped_lock<std::mutex> lock(mutex_);
        stream_ = &os;
    }

    void Logger::log(LogLevel level, const std::string& message) {
        LogEvent event(level, message);
        std::scoped_lock<std::mutex> lock(mutex_);

        *stream_ << event.toString() << "\n";
        stream_->flush();
    }


} // namespace core::utils