#include "tests.h"
#include "logger.hpp"
#include "log_event.hpp"

#include <sstream>
#include <string>
#include <thread>
#include <vector>

using core::utils::Logger;
using core::utils::LogLevel;
using core::utils::LogEvent;

// Helper: reset the logger to a fresh stringstream and return a pointer to it
static std::ostringstream* initLoggerToStringStream() {
    static std::ostringstream oss;
    oss.str("");
    oss.clear();
    Logger::getInstance().init(oss);
    Logger::getInstance().setLogLevel(LogLevel::DEBUG); // Reset to log everything
    return &oss;
}

// Basic: single log message contains the right level and message
bool LoggerTest_SingleMessage() {
    auto* oss = initLoggerToStringStream();
    Logger::getInstance().log(LogLevel::INFO, "hello world");

    std::string output = oss->str();
    bool hasLevel   = output.find("[INFO]") != std::string::npos;
    bool hasMessage = output.find("hello world") != std::string::npos;

    return test_helper("1", std::to_string(hasLevel && hasMessage));
}

// Each log level appears correctly in output
bool LoggerTest_AllLevels() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.log(LogLevel::EMERGENCY, "emg");
    logger.log(LogLevel::ALERT,     "alt");
    logger.log(LogLevel::CRITICAL,  "crt");
    logger.log(LogLevel::ERROR,     "err");
    logger.log(LogLevel::WARNING,   "wrn");
    logger.log(LogLevel::NOTICE,    "ntc");
    logger.log(LogLevel::INFO,      "inf");
    logger.log(LogLevel::DEBUG,     "dbg");

    std::string output = oss->str();
    bool all = output.find("[EMERGENCY]") != std::string::npos
            && output.find("[ALERT]")     != std::string::npos
            && output.find("[CRITICAL]")  != std::string::npos
            && output.find("[ERROR]")     != std::string::npos
            && output.find("[WARNING]")   != std::string::npos
            && output.find("[NOTICE]")    != std::string::npos
            && output.find("[INFO]")      != std::string::npos
            && output.find("[DEBUG]")     != std::string::npos;

    return test_helper("1", std::to_string(all));
}

// Output contains a timestamp in the expected format
bool LoggerTest_TimestampPresent() {
    auto* oss = initLoggerToStringStream();
    Logger::getInstance().log(LogLevel::INFO, "ts_test");

    std::string output = oss->str();
    bool hasTimestamp = false;
    auto pos = output.find("[20");
    if (pos != std::string::npos && output.find("-", pos) != std::string::npos) {
        hasTimestamp = true;
    }

    return test_helper("1", std::to_string(hasTimestamp));
}

// Multiple messages all appear in the output
bool LoggerTest_MultipleMessages() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    for (int i = 0; i < 10; ++i) {
        logger.log(LogLevel::INFO, "msg_" + std::to_string(i));
    }

    std::string output = oss->str();
    bool allPresent = true;
    for (int i = 0; i < 10; ++i) {
        if (output.find("msg_" + std::to_string(i)) == std::string::npos) {
            allPresent = false;
            break;
        }
    }

    return test_helper("1", std::to_string(allPresent));
}

// Multithreaded: N threads each write M messages, all N*M must appear
bool LoggerTest_MT_AllEventsWritten() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    constexpr int NUM_THREADS     = 8;
    constexpr int MSGS_PER_THREAD = 50;

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&logger, t]() {
            for (int m = 0; m < MSGS_PER_THREAD; ++m) {
                logger.log(LogLevel::INFO,
                           "t" + std::to_string(t) + "_m" + std::to_string(m));
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    std::string output = oss->str();
    int found = 0;
    for (int t = 0; t < NUM_THREADS; ++t) {
        for (int m = 0; m < MSGS_PER_THREAD; ++m) {
            std::string tag = "t" + std::to_string(t) + "_m" + std::to_string(m);
            if (output.find(tag) != std::string::npos) {
                found++;
            }
        }
    }

    int expected = NUM_THREADS * MSGS_PER_THREAD;
    return test_helper(std::to_string(expected), std::to_string(found));
}

// Multithreaded: no lines are garbled
bool LoggerTest_MT_NoGarbledLines() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    constexpr int NUM_THREADS     = 4;
    constexpr int MSGS_PER_THREAD = 100;

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&logger, t]() {
            for (int m = 0; m < MSGS_PER_THREAD; ++m) {
                logger.log(LogLevel::WARNING,
                           "thread" + std::to_string(t) + "_line" + std::to_string(m));
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    std::string output = oss->str();
    std::istringstream stream(output);
    std::string line;
    int totalLines = 0;
    int validLines = 0;

    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        totalLines++;

        bool startsCorrectly = line.find("[WARNING]") == 0;
        int count = 0;
        std::size_t pos = 0;
        while ((pos = line.find("[WARNING]", pos)) != std::string::npos) {
            count++;
            pos += 9;
        }

        if (startsCorrectly && count == 1) {
            validLines++;
        }
    }

    int expected = NUM_THREADS * MSGS_PER_THREAD;
    bool correct = (totalLines == expected) && (validLines == expected);
    return test_helper("1", std::to_string(correct));
}

// =========================================================================
// setLogLevel Tests
// =========================================================================

// Setting WARNING should filter out NOTICE, INFO, DEBUG
bool LoggerTest_SetLevel_FiltersBelowThreshold() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::WARNING);

    logger.log(LogLevel::NOTICE, "should_not_appear");
    logger.log(LogLevel::INFO,   "should_not_appear");
    logger.log(LogLevel::DEBUG,  "should_not_appear");

    std::string output = oss->str();
    bool clean = output.find("should_not_appear") == std::string::npos;

    return test_helper("1", std::to_string(clean));
}

// Events at exactly the threshold level should be logged
bool LoggerTest_SetLevel_AllowsAtThreshold() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::WARNING);

    logger.log(LogLevel::EMERGENCY, "emg");
    logger.log(LogLevel::ALERT,     "alt");
    logger.log(LogLevel::CRITICAL,  "crt");
    logger.log(LogLevel::ERROR,     "err");
    logger.log(LogLevel::WARNING,   "wrn");

    std::string output = oss->str();
    bool all = output.find("[EMERGENCY]") != std::string::npos
            && output.find("[ALERT]")     != std::string::npos
            && output.find("[CRITICAL]")  != std::string::npos
            && output.find("[ERROR]")     != std::string::npos
            && output.find("[WARNING]")   != std::string::npos;

    return test_helper("1", std::to_string(all));
}

// EMERGENCY threshold should only log EMERGENCY
bool LoggerTest_SetLevel_EmergencyOnly() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::EMERGENCY);

    logger.log(LogLevel::EMERGENCY, "critical_failure");
    logger.log(LogLevel::ALERT,     "nope");
    logger.log(LogLevel::CRITICAL,  "nope");
    logger.log(LogLevel::ERROR,     "nope");
    logger.log(LogLevel::WARNING,   "nope");
    logger.log(LogLevel::NOTICE,    "nope");
    logger.log(LogLevel::INFO,      "nope");
    logger.log(LogLevel::DEBUG,     "nope");

    std::string output = oss->str();

    bool hasEmergency = output.find("[EMERGENCY]") != std::string::npos;
    // Count newlines to verify only one message was written
    int lineCount = 0;
    for (char c : output) {
        if (c == '\n') lineCount++;
    }

    return test_helper("1", std::to_string(hasEmergency && lineCount == 1));
}

// DEBUG threshold should log everything
bool LoggerTest_SetLevel_DebugLogsEverything() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::DEBUG);

    logger.log(LogLevel::EMERGENCY, "emg");
    logger.log(LogLevel::ALERT,     "alt");
    logger.log(LogLevel::CRITICAL,  "crt");
    logger.log(LogLevel::ERROR,     "err");
    logger.log(LogLevel::WARNING,   "wrn");
    logger.log(LogLevel::NOTICE,    "ntc");
    logger.log(LogLevel::INFO,      "inf");
    logger.log(LogLevel::DEBUG,     "dbg");

    std::string output = oss->str();
    int lineCount = 0;
    for (char c : output) {
        if (c == '\n') lineCount++;
    }

    return test_helper("8", std::to_string(lineCount));
}

// Changing the level mid-stream should take effect immediately
bool LoggerTest_SetLevel_ChangesMidStream() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    logger.setLogLevel(LogLevel::DEBUG);
    logger.log(LogLevel::DEBUG, "visible");

    logger.setLogLevel(LogLevel::ERROR);
    logger.log(LogLevel::DEBUG,   "filtered_out");
    logger.log(LogLevel::WARNING, "filtered_out");
    logger.log(LogLevel::ERROR,   "still_visible");

    std::string output = oss->str();

    bool hasVisible     = output.find("visible")      != std::string::npos;
    bool hasStill       = output.find("still_visible") != std::string::npos;
    bool noFiltered     = output.find("filtered_out") == std::string::npos;

    return test_helper("1", std::to_string(hasVisible && hasStill && noFiltered));
}

// =========================================================================
// LogEvent Comparison Tests
// =========================================================================

// More severe (lower enum value) should compare as less-than
bool LoggerTest_LogEvent_SeverityOrdering() {
    LogEvent emergency{LogLevel::EMERGENCY, "emg"};
    LogEvent warning{LogLevel::WARNING, "wrn"};
    LogEvent debug{LogLevel::DEBUG, "dbg"};

    bool emergencyBeforeWarning = (emergency < warning);
    bool warningBeforeDebug     = (warning < debug);
    bool emergencyBeforeDebug   = (emergency < debug);
    bool debugNotBeforeEmergency = !(debug < emergency);

    bool all = emergencyBeforeWarning
            && warningBeforeDebug
            && emergencyBeforeDebug
            && debugNotBeforeEmergency;

    return test_helper("1", std::to_string(all));
}

// Same severity: earlier timestamp should compare as less-than
bool LoggerTest_LogEvent_TimestampBreaksTie() {
    LogEvent first{LogLevel::ERROR, "first"};

    // Small busy-wait to ensure a different timestamp
    auto start = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now() == start) {}

    LogEvent second{LogLevel::ERROR, "second"};

    bool firstBeforeSecond  = (first < second);
    bool notEqual           = (first != second);
    bool secondNotBeforeFirst = !(second < first);

    bool all = firstBeforeSecond && notEqual && secondNotBeforeFirst;

    return test_helper("1", std::to_string(all));
}