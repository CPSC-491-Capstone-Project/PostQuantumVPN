#ifndef _PQVPN_TESTS_CLIENT_TESTS_HPP_
#define _PQVPN_TESTS_CLIENT_TESTS_HPP_

#include "test_utils.hpp"
#include "client.hpp"
#include "logger.hpp"

using core::utils::Logger;

// =============================================================================
// Test 1: Init with loopback server endpoint succeeds; socket and poller open.
// =============================================================================
bool ClientTest_Init_Loopback_Succeeds() {
    client::Client c;

    if (!c.Init("127.0.0.1", 51820)) {
        Logger::Error("ClientTest1: Init failed");
        return false;
    }
    if (!c.IsInitialized()) {
        Logger::Error("ClientTest1: IsInitialized false after successful Init");
        return false;
    }

    c.Shutdown();
    return true;
}

// =============================================================================
// Test 2: Stop before Run — Run() returns immediately without blocking.
// =============================================================================
bool ClientTest_StopBeforeRun() {
    client::Client c;

    if (!c.Init("127.0.0.1", 51820)) {
        Logger::Error("ClientTest2: Init failed");
        return false;
    }

    c.Stop();
    c.Run(); // must return immediately, not block

    c.Shutdown();
    return true;
}

// =============================================================================
// Test 3: Shutdown closes handles cleanly.  Double Shutdown does not crash.
// =============================================================================
bool ClientTest_DoubleShutdown() {
    client::Client c;

    if (!c.Init("127.0.0.1", 51820)) {
        Logger::Error("ClientTest3: Init failed");
        return false;
    }

    c.Shutdown();

    if (c.IsInitialized()) {
        Logger::Error("ClientTest3: IsInitialized true after Shutdown");
        return false;
    }

    c.Shutdown(); // must not crash
    return true;
}

#endif // _PQVPN_TESTS_CLIENT_TESTS_HPP_
