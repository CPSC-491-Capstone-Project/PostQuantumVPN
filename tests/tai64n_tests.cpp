#include "tests.h"
#include "tai64n.hpp"

#include <functional>
#include <latch>
#include <set>
#include <string>
#include <thread>
#include <vector>

using core::utils::Tai64n;
using core::utils::Tai64nStamp;

// ============================================================================
// TAI64N Tests
// ============================================================================

bool Tai64nTest_SingleThread_UniqueTimestamps() {
    Tai64n clock;
    std::set<std::array<uint8_t, Tai64nStamp::kSize>> seen;

    for (int i = 0; i < 10; ++i) {
        auto stamp = clock.Now();
        seen.insert(stamp.Data());
    }

    return seen.size() == 10;
}

bool Tai64nTest_MT_AllUnique(std::function<void()> startTimer) {
    constexpr int kCallsPerThread = 1000;
    const auto nThreads = std::max(1u, std::thread::hardware_concurrency());

    Tai64n clock;
    std::vector<std::vector<std::array<uint8_t, Tai64nStamp::kSize>>> results(nThreads);
    for (auto& v : results) v.reserve(kCallsPerThread);

    std::latch gate(1);
    std::vector<std::jthread> threads;
    threads.reserve(nThreads);

    for (unsigned t = 0; t < nThreads; ++t) {
        threads.emplace_back([&, t] {
            gate.wait();
            for (int i = 0; i < kCallsPerThread; ++i) {
                results[t].push_back(clock.Now().Data());
            }
        });
    }

    startTimer();
    gate.count_down();

    for (auto& th : threads) th.join();

    std::set<std::array<uint8_t, Tai64nStamp::kSize>> seen;
    for (const auto& v : results)
        for (const auto& s : v)
            seen.insert(s);

    return seen.size() == static_cast<std::size_t>(nThreads * kCallsPerThread);
}

bool Tai64nTest_MT_Throughput(std::function<void()> startTimer) {
    constexpr int kCallsPerThread = 100'000;
    const auto nThreads = std::max(1u, std::thread::hardware_concurrency());

    Tai64n clock;

    std::latch gate(1);
    std::vector<std::jthread> threads;
    threads.reserve(nThreads);

    for (unsigned t = 0; t < nThreads; ++t) {
        threads.emplace_back([&] {
            gate.wait();
            for (int i = 0; i < kCallsPerThread; ++i) {
                auto stamp = clock.Now();
                (void)stamp;
            }
        });
    }

    startTimer();
    gate.count_down();

    for (auto& th : threads) th.join();

    return true;
}