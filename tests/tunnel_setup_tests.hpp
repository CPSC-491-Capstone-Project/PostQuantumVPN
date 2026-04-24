#ifndef _PQVPN_TESTS_TUNNEL_SETUP_TESTS_HPP_
#define _PQVPN_TESTS_TUNNEL_SETUP_TESTS_HPP_

#include "test_utils.hpp"
#include "privileges.hpp"
#include "tunnel_setup.hpp"
#include "tun_device.hpp"
#include "logger.hpp"

#include <string>

using core::utils::Logger;

static bool TunnelTest_IsPrivileged() {
    if (!core::os::HasElevatedPrivileges()) {
        Logger::Emergency("TunnelSetup tests require root — re-run as: sudo ./run-tests");
        return false;
    }
    return true;
}

// =============================================================================
// Test 1: HasElevatedPrivileges reflects actual process euid
// =============================================================================
bool TunnelSetupTest_HasElevatedPrivileges_ReflectsEuid() {
    bool result = core::os::HasElevatedPrivileges();
    bool is_root = (::geteuid() == 0);
    if (result != is_root) {
        Logger::Error("TunnelSetupTest_HasElevatedPrivileges: mismatch with geteuid()");
        return false;
    }
    return true;
}

// =============================================================================
// Test 2: ConfigureClientRouting fails gracefully on nonexistent interface
// =============================================================================
bool TunnelSetupTest_ConfigureClientRouting_FailsOnMissingIface() {
    if (!TunnelTest_IsPrivileged()) return false;

    bool ok = core::network::ConfigureClientRouting("tun_vpntest_nosuch", 51820, 200);
    if (ok) {
        Logger::Error("TunnelSetupTest: ConfigureClientRouting should fail on nonexistent iface");
        core::network::RemoveClientRouting("tun_vpntest_nosuch", 51820, 200);
        return false;
    }
    return true;
}

// =============================================================================
// Test 3: ConfigureClientRouting + RemoveClientRouting round-trip
// =============================================================================
bool TunnelSetupTest_ClientRouting_Roundtrip() {
    if (!TunnelTest_IsPrivileged()) return false;

    static constexpr const char* kIface = "tun_vpntest_r0";
    static constexpr uint32_t    kMark  = 55555;
    static constexpr int         kTable = 201;
    static const core::network::IPv4 kIP{10, 199, 77, 1};

    core::network::TunDevice dev;
    if (!dev.Open(kIface)) {
        Logger::Error("TunnelSetupTest_ClientRouting_Roundtrip: failed to open TUN");
        return false;
    }
    if (!dev.BringUp(kIP)) {
        Logger::Error("TunnelSetupTest_ClientRouting_Roundtrip: failed to bring up TUN");
        dev.Close();
        return false;
    }

    bool ok = core::network::ConfigureClientRouting(kIface, kMark, kTable);
    core::network::RemoveClientRouting(kIface, kMark, kTable);
    dev.Close();

    if (!ok) {
        Logger::Error("TunnelSetupTest_ClientRouting_Roundtrip: ConfigureClientRouting failed");
        return false;
    }
    return true;
}

// =============================================================================
// Test 4: RemoveClientRouting is idempotent (no crash on double-remove)
// =============================================================================
bool TunnelSetupTest_RemoveClientRouting_Idempotent() {
    if (!TunnelTest_IsPrivileged()) return false;

    static constexpr uint32_t kMark  = 55556;
    static constexpr int      kTable = 202;

    core::network::RemoveClientRouting("tun_vpntest_r1", kMark, kTable);
    core::network::RemoveClientRouting("tun_vpntest_r1", kMark, kTable);
    return true;
}

#endif // _PQVPN_TESTS_TUNNEL_SETUP_TESTS_HPP_
