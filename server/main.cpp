#include "logger.hpp"
#include "server.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <chrono>

using core::utils::Logger;
using core::network::IPv4;
using server::Server;

// =============================================================================
// Minimal test harness (matches test_runner color scheme)
// =============================================================================

static const char* GREEN = "\033[32m";
static const char* RED   = "\033[31m";
static const char* CYAN  = "\033[36m";
static const char* RESET = "\033[0m";

static int total  = 0;
static int passed = 0;
static int failed = 0;

static void Check(bool result, const std::string& name) {
    total++;
    std::cout << CYAN << "[TEST] " << RESET << name << " ... ";
    if (result) {
        passed++;
        std::cout << GREEN << "[PASS]" << RESET << "\n";
    } else {
        failed++;
        std::cout << RED << "[FAIL]" << RESET << "\n";
    }
}

// =============================================================================
// Tests
// =============================================================================

/// Init on loopback succeeds; socket and poller report open.
static bool Test_InitSucceeds() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);  // ephemeral port

    if (!srv.Init()) return false;
    if (!srv.IsInitialized()) return false;
    if (!srv.GetSocket().IsOpen()) return false;
    if (!srv.GetPoller().IsOpen()) return false;

    srv.Shutdown();
    return true;
}

/// Init with an invalid address fails and does not leave things half-open.
static bool Test_InitInvalidAddress() {
    Server srv;
    srv.SetBindAddress(IPv4(std::string("not.an.ip")))
       .SetPort(0);

    if (srv.Init()) return false;  // should fail
    if (srv.IsInitialized()) return false;
    if (srv.GetSocket().IsOpen()) return false;
    if (srv.GetPoller().IsOpen()) return false;

    return true;
}

/// Double Init returns false on the second call.
static bool Test_DoubleInit() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (srv.Init()) return false;  // second Init should fail

    srv.Shutdown();
    return true;
}

/// Run starts the event loop on a background thread.
static bool Test_RunSucceeds() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (!srv.Run()) return false;
    if (!srv.IsRunning()) return false;

    srv.Shutdown();
    return true;
}

/// Run without Init fails.
static bool Test_RunBeforeInit() {
    Server srv;
    if (srv.Run()) return false;  // should fail
    return true;
}

/// Double Run returns false on the second call.
static bool Test_DoubleRun() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (!srv.Run()) return false;
    if (srv.Run()) return false;  // second Run should fail

    srv.Shutdown();
    return true;
}

/// Stop before Run — Run returns immediately without blocking.
static bool Test_StopBeforeRun() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;

    srv.Stop();

    // Run should refuse to start after Stop
    if (srv.Run()) return false;

    srv.Shutdown();
    return true;
}

/// Shutdown closes both handles.
static bool Test_ShutdownCloses() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (!srv.Run()) return false;

    srv.Shutdown();

    if (srv.IsRunning()) return false;
    if (srv.IsInitialized()) return false;
    if (srv.GetSocket().IsOpen()) return false;
    if (srv.GetPoller().IsOpen()) return false;

    return true;
}

/// Double Shutdown does not crash.
static bool Test_DoubleShutdown() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (!srv.Run()) return false;

    srv.Shutdown();
    srv.Shutdown();  // should not crash or throw

    return true;
}

/// Shutdown without Run (init-only) cleans up cleanly.
static bool Test_ShutdownWithoutRun() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    srv.Shutdown();

    if (srv.GetSocket().IsOpen()) return false;
    if (srv.GetPoller().IsOpen()) return false;

    return true;
}

/// After Shutdown, server can be re-initialized and run again.
static bool Test_ReinitAfterShutdown() {
    Server srv;
    srv.SetBindAddress(IPv4::Loopback())
       .SetPort(0);

    if (!srv.Init()) return false;
    if (!srv.Run()) return false;
    srv.Shutdown();

    // Re-init on a fresh ephemeral port
    srv.SetPort(0);
    if (!srv.Init()) return false;
    if (!srv.Run()) return false;

    srv.Shutdown();
    return true;
}

/// Builder chaining returns the same object.
static bool Test_BuilderChaining() {
    Server srv;
    Server& ref = srv.SetBindAddress(IPv4::Loopback())
                     .SetPort(0)
                     .SetPollTimeoutMs(100);

    return &ref == &srv;
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    Logger::getInstance().init(std::cerr);

    std::cout << "========================================\n";
    std::cout << "Server Lifecycle Tests\n";
    std::cout << "========================================\n\n";

    Check(Test_InitSucceeds(),        "Init on loopback succeeds");
    Check(Test_InitInvalidAddress(),  "Init with invalid address fails");
    Check(Test_DoubleInit(),          "Double Init returns false");
    Check(Test_RunSucceeds(),         "Run starts event loop");
    Check(Test_RunBeforeInit(),       "Run before Init fails");
    Check(Test_DoubleRun(),           "Double Run returns false");
    Check(Test_StopBeforeRun(),       "Stop before Run — exits immediately");
    Check(Test_ShutdownCloses(),      "Shutdown closes socket and poller");
    Check(Test_DoubleShutdown(),      "Double Shutdown does not crash");
    Check(Test_ShutdownWithoutRun(),  "Shutdown without Run cleans up");
    Check(Test_ReinitAfterShutdown(), "Re-init after Shutdown works");
    Check(Test_BuilderChaining(),     "Builder chaining returns same ref");

    std::cout << "\n========================================\n";
    std::cout << "Total:  " << total  << "\n";
    std::cout << GREEN << "Passed: " << passed << RESET << "\n";
    std::cout << RED   << "Failed: " << failed << RESET << "\n\n";

    return failed > 0 ? 1 : 0;
}