#include "tests.h"
#include "logger.hpp"

#include <sstream>
#include <string>
#include <thread>
#include <vector>

using core::utils::Logger;
using core::utils::LogLevel;

// Helper: reset the logger to a fresh stringstream and return a pointer to it
static std::ostringstream* initLoggerToStringStream() {
    static std::ostringstream oss;
    oss.str("");
    oss.clear();
    Logger::getInstance().init(oss);
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

    logger.log(LogLevel::DEBUG, "d");
    logger.log(LogLevel::INFO,  "i");
    logger.log(LogLevel::WARN,  "w");
    logger.log(LogLevel::ERROR, "e");

    std::string output = oss->str();
    bool all = output.find("[DEBUG]") != std::string::npos
            && output.find("[INFO]")  != std::string::npos
            && output.find("[WARN]")  != std::string::npos
            && output.find("[ERROR]") != std::string::npos;

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

// Multithreaded: N threads each write M messages, all N*M must appear (any order)
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

// Multithreaded: no lines are garbled (each line has exactly one valid log format)
bool LoggerTest_MT_NoGarbledLines() {
    auto* oss = initLoggerToStringStream();
    auto& logger = Logger::getInstance();

    constexpr int NUM_THREADS     = 4;
    constexpr int MSGS_PER_THREAD = 100;

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&logger, t]() {
            for (int m = 0; m < MSGS_PER_THREAD; ++m) {
                logger.log(LogLevel::WARN,
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

        bool startsCorrectly = line.find("[WARN]") == 0;
        int count = 0;
        std::size_t pos = 0;
        while ((pos = line.find("[WARN]", pos)) != std::string::npos) {
            count++;
            pos += 6;
        }

        if (startsCorrectly && count == 1) {
            validLines++;
        }
    }

    int expected = NUM_THREADS * MSGS_PER_THREAD;
    bool correct = (totalLines == expected) && (validLines == expected);
    return test_helper("1", std::to_string(correct));
}