// Tests in this file require CAP_NET_ADMIN (run as root or with sudo).
// If the process is not privileged every test fails and logs a message:
//
//     sudo ./run-tests
//
// Only interfaces whose names begin with "tun_vpntest" are created.
// All created interfaces are destroyed automatically when TunDevice closes
// its fd (IFF_PERSIST is never set) — RAII handles all cleanup.

#ifndef _PQVPN_TESTS_TUN_DEVICE_TESTS_HPP_
#define _PQVPN_TESTS_TUN_DEVICE_TESTS_HPP_

#include "test_utils.hpp"
#include "tun_device.hpp"
#include "udp_socket.hpp"
#include "event_poller.hpp"
#include "logger.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace core::network;
using core::utils::Logger;

// =============================================================================
// Shared helpers
// =============================================================================

static bool TunTest_IsPrivileged() {
    if (!TunDevice::HasRequiredPrivileges()) {
        Logger::Emergency(
            "TunDevice tests require CAP_NET_ADMIN — "
            "re-run the test suite as root:  sudo ./run-tests");
        return false;
    }
    return true;
}

static constexpr const char* kTunIface  = "tun_vpntest0";
static constexpr const char* kTunIface2 = "tun_vpntest1";
static const     IPv4        kTunIP{10, 199, 1, 1};
static const     IPv4        kTunDst{10, 199, 1, 2};  // in /24, routes via tun_vpntest0

// =============================================================================
// Test 1: Full open/close lifecycle
// =============================================================================
bool TunDeviceTest_OpenClose() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) {
        Logger::Error("TunDeviceTest_OpenClose: " + std::string(kTunIface) + " already exists");
        return false;
    }

    TunDevice dev;
    if (dev.IsOpen())                      { Logger::Error("TunDeviceTest_OpenClose: new device should not be open"); return false; }
    if (dev.GetHandle() != kInvalidHandle) { Logger::Error("TunDeviceTest_OpenClose: new device handle should be invalid"); return false; }

    if (!dev.Open(kTunIface))              { Logger::Error("TunDeviceTest_OpenClose: Open failed"); return false; }
    if (!dev.IsOpen())                     { Logger::Error("TunDeviceTest_OpenClose: not open after Open()"); return false; }
    if (dev.GetHandle() == kInvalidHandle) { Logger::Error("TunDeviceTest_OpenClose: handle invalid after Open()"); return false; }
    if (!TunDevice::Exists(kTunIface))     { Logger::Error("TunDeviceTest_OpenClose: interface not visible in OS after Open()"); return false; }

    dev.Close();
    if (dev.IsOpen())                      { Logger::Error("TunDeviceTest_OpenClose: still open after Close()"); return false; }
    if (dev.GetHandle() != kInvalidHandle) { Logger::Error("TunDeviceTest_OpenClose: handle not invalid after Close()"); return false; }
    if (TunDevice::Exists(kTunIface))      { Logger::Error("TunDeviceTest_OpenClose: interface still visible after Close()"); return false; }

    return true;
}

// =============================================================================
// Test 2: Opening an already-open device returns false — device stays intact
// =============================================================================
bool TunDeviceTest_OpenAlreadyOpen() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_OpenAlreadyOpen: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface)) { Logger::Error("TunDeviceTest_OpenAlreadyOpen: first Open failed"); return false; }

    Logger::Info("TunDeviceTest_OpenAlreadyOpen: === Expecting a warning log below (intentional) ===");
    if (dev.Open(kTunIface))  { Logger::Error("TunDeviceTest_OpenAlreadyOpen: second Open should return false"); return false; }
    if (!dev.IsOpen())        { Logger::Error("TunDeviceTest_OpenAlreadyOpen: device should remain open after rejected second Open"); return false; }

    return true;
}

// =============================================================================
// Test 3: Double Close — no crash, correct state
// =============================================================================
bool TunDeviceTest_DoubleClose() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_DoubleClose: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface)) { Logger::Error("TunDeviceTest_DoubleClose: Open failed"); return false; }
    dev.Close();
    dev.Close();
    return !dev.IsOpen() && dev.GetHandle() == kInvalidHandle;
}

// =============================================================================
// Test 4: Move-construct — source invalidated, destination owns the handle
// =============================================================================
bool TunDeviceTest_MoveConstruct() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_MoveConstruct: interface pre-exists"); return false; }

    TunDevice src;
    if (!src.Open(kTunIface)) { Logger::Error("TunDeviceTest_MoveConstruct: Open failed"); return false; }
    const Handle h = src.GetHandle();

    TunDevice dst{std::move(src)};

    if (src.IsOpen())                      { Logger::Error("TunDeviceTest_MoveConstruct: src still open after move"); return false; }
    if (src.GetHandle() != kInvalidHandle) { Logger::Error("TunDeviceTest_MoveConstruct: src handle not invalid after move"); return false; }
    if (!dst.IsOpen())                     { Logger::Error("TunDeviceTest_MoveConstruct: dst not open after move"); return false; }
    if (dst.GetHandle() != h)              { Logger::Error("TunDeviceTest_MoveConstruct: dst handle mismatch"); return false; }
    if (!TunDevice::Exists(kTunIface))     { Logger::Error("TunDeviceTest_MoveConstruct: interface disappeared after move"); return false; }

    return true;
}

// =============================================================================
// Test 5: Move-assign — closes the owned fd before taking new ownership
// =============================================================================
bool TunDeviceTest_MoveAssign() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface))  { Logger::Error("TunDeviceTest_MoveAssign: kTunIface pre-exists"); return false; }
    if (TunDevice::Exists(kTunIface2)) { Logger::Error("TunDeviceTest_MoveAssign: kTunIface2 pre-exists"); return false; }

    TunDevice src, dst;
    if (!src.Open(kTunIface))  { Logger::Error("TunDeviceTest_MoveAssign: src Open failed"); return false; }
    if (!dst.Open(kTunIface2)) { Logger::Error("TunDeviceTest_MoveAssign: dst Open failed"); return false; }

    const Handle src_handle = src.GetHandle();
    dst = std::move(src);

    if (src.IsOpen())                  { Logger::Error("TunDeviceTest_MoveAssign: src still open after move"); return false; }
    if (!dst.IsOpen())                 { Logger::Error("TunDeviceTest_MoveAssign: dst not open after move"); return false; }
    if (dst.GetHandle() != src_handle) { Logger::Error("TunDeviceTest_MoveAssign: dst handle mismatch"); return false; }

    // kTunIface2's fd was closed by move-assign when it replaced dst — must be gone
    if (TunDevice::Exists(kTunIface2)) {
        Logger::Error("TunDeviceTest_MoveAssign: kTunIface2 still exists — move-assign did not close the old fd");
        return false;
    }

    return true;
}

// =============================================================================
// Test 6: SetNonBlocking — Read on empty TUN returns EAGAIN/EWOULDBLOCK
// =============================================================================
bool TunDeviceTest_SetNonBlocking() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_SetNonBlocking: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))  { Logger::Error("TunDeviceTest_SetNonBlocking: Open failed"); return false; }
    if (!dev.SetNonBlocking()) { Logger::Error("TunDeviceTest_SetNonBlocking: SetNonBlocking failed"); return false; }

    std::vector<uint8_t> buf(2048);
    BytesTransferred n = dev.Read(buf);
    if (n >= 0) {
        Logger::Error("TunDeviceTest_SetNonBlocking: expected -1 on empty non-blocking Read, got " + std::to_string(n));
        return false;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        Logger::Error("TunDeviceTest_SetNonBlocking: unexpected errno " + std::to_string(errno));
        return false;
    }

    return true;
}

// =============================================================================
// Test 7: Write — inject a packet via TUN; local UDPSocket receives it
//
// TunDevice::Write() hands an IP packet to the kernel's receive path for
// tun_vpntest0.  This simulates an encrypted VPN packet arriving from a peer:
// after decryption the plaintext packet is written to TUN and delivered to the
// destination socket as if it arrived from the network.
// =============================================================================
bool TunDeviceTest_Write_InjectAndReceive() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_Write_InjectAndReceive: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))        { Logger::Error("TunDeviceTest_Write_InjectAndReceive: Open failed"); return false; }
    if (!dev.BringUp(kTunIP))        { Logger::Error("TunDeviceTest_Write_InjectAndReceive: BringUp failed"); return false; }

    // UDP socket bound to the TUN address — the "local application" receiving the injected packet
    UDPSocket udp;
    if (!udp.Open())                 { Logger::Error("TunDeviceTest_Write_InjectAndReceive: UDPSocket Open failed"); return false; }
    if (!udp.Bind(kTunIP, 0))        { Logger::Error("TunDeviceTest_Write_InjectAndReceive: UDPSocket Bind failed"); return false; }
    if (!udp.SetNonBlocking())       { Logger::Error("TunDeviceTest_Write_InjectAndReceive: UDPSocket SetNonBlocking failed"); return false; }

    const uint16_t dst_port = udp.GetLocalEndpoint().value().port;

    // Wait for the UDP socket to become readable via EventPoller
    EventPoller poller;
    if (!poller.Open())                                        { Logger::Error("TunDeviceTest_Write_InjectAndReceive: poller Open failed"); return false; }
    if (!poller.Add(udp.GetHandle(), EventMask::Readable))     { Logger::Error("TunDeviceTest_Write_InjectAndReceive: poller Add failed"); return false; }

    const std::array<uint8_t, 6> payload{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    auto pkt = TunDevice::BuildUdpPacket(kTunDst, kTunIP, 9999, dst_port, payload);

    BytesTransferred written = dev.Write(pkt);
    if (written != static_cast<BytesTransferred>(pkt.size())) {
        Logger::Error("TunDeviceTest_Write_InjectAndReceive: Write returned " + std::to_string(written)
                      + ", expected " + std::to_string(pkt.size()));
        return false;
    }

    std::array<PollEvent, 2> events{};
    if (poller.Poll(events, 2000) < 1) {
        Logger::Error("TunDeviceTest_Write_InjectAndReceive: UDP socket not readable within 2s after Write");
        return false;
    }

    std::vector<uint8_t> recv_buf(256);
    auto result = udp.ReceiveFrom(recv_buf);
    if (!result) { Logger::Error("TunDeviceTest_Write_InjectAndReceive: ReceiveFrom returned nullopt"); return false; }
    if (result->bytes_read != payload.size()) {
        Logger::Error("TunDeviceTest_Write_InjectAndReceive: received " + std::to_string(result->bytes_read)
                      + " bytes, expected " + std::to_string(payload.size()));
        return false;
    }
    if (memcmp(recv_buf.data(), payload.data(), payload.size()) != 0) {
        Logger::Error("TunDeviceTest_Write_InjectAndReceive: payload mismatch");
        return false;
    }

    return true;
}

// =============================================================================
// Test 8: Read — outbound packet from a local UDPSocket appears on TUN fd
//
// When a UDPSocket bound to kTunIP sends to kTunDst (in the /24 subnet), the
// kernel routes it through tun_vpntest0.  TunDevice::Read() captures the IP
// packet — exactly how the VPN reads plaintext outbound traffic before
// encrypting and forwarding it to the peer.
// =============================================================================
bool TunDeviceTest_Read_CaptureOutbound() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_Read_CaptureOutbound: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))        { Logger::Error("TunDeviceTest_Read_CaptureOutbound: Open failed"); return false; }
    if (!dev.SetNonBlocking())       { Logger::Error("TunDeviceTest_Read_CaptureOutbound: SetNonBlocking failed"); return false; }
    if (!dev.BringUp(kTunIP))        { Logger::Error("TunDeviceTest_Read_CaptureOutbound: BringUp failed"); return false; }

    // Drain kernel-generated packets (IGMP membership reports) placed on TUN fd during BringUp
    {
        std::vector<uint8_t> drain(4096);
        while (dev.Read(drain) > 0) {}
    }

    // Poll the TUN fd so we don't block forever
    EventPoller poller;
    if (!poller.Open())                                       { Logger::Error("TunDeviceTest_Read_CaptureOutbound: poller Open failed"); return false; }
    if (!poller.Add(dev.GetHandle(), EventMask::Readable))    { Logger::Error("TunDeviceTest_Read_CaptureOutbound: poller Add failed"); return false; }

    // Send to kTunDst — kernel routes via tun_vpntest0, packet appears on TUN fd
    UDPSocket udp;
    if (!udp.Open())          { Logger::Error("TunDeviceTest_Read_CaptureOutbound: UDPSocket Open failed"); return false; }
    if (!udp.Bind(kTunIP, 0)) { Logger::Error("TunDeviceTest_Read_CaptureOutbound: UDPSocket Bind failed"); return false; }

    std::array<uint8_t, 4> ping{0x01, 0x02, 0x03, 0x04};
    udp.SendTo({kTunDst, 12345}, ping);

    std::array<PollEvent, 2> events{};
    if (poller.Poll(events, 3000) < 1) {
        Logger::Error("TunDeviceTest_Read_CaptureOutbound: TUN fd not readable within 3s — packet did not route via " + std::string(kTunIface));
        return false;
    }

    std::vector<uint8_t> tun_buf(4096);
    BytesTransferred n = dev.Read(tun_buf);
    if (n < 20) {
        Logger::Error("TunDeviceTest_Read_CaptureOutbound: Read returned " + std::to_string(n) + " (expected >= 20 for IP header)");
        return false;
    }

    auto captured_dst = TunDevice::ParseDstIP({tun_buf.data(), static_cast<std::size_t>(n)});
    if (!captured_dst) { Logger::Error("TunDeviceTest_Read_CaptureOutbound: ParseDstIP returned nullopt"); return false; }
    if (*captured_dst != kTunDst) {
        Logger::Error("TunDeviceTest_Read_CaptureOutbound: dst IP mismatch — got "
                      + captured_dst->ToString() + ", expected " + kTunDst.ToString());
        return false;
    }

    return true;
}

// =============================================================================
// Test 9: Write large packet (1400-byte payload — typical VPN MTU)
//
// Confirms that a near-MTU injection reaches the receiving UDPSocket intact,
// ruling out silent truncation or fragmentation at the TUN layer.
// =============================================================================
bool TunDeviceTest_Write_LargePacket() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_Write_LargePacket: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))  { Logger::Error("TunDeviceTest_Write_LargePacket: Open failed"); return false; }
    if (!dev.BringUp(kTunIP))  { Logger::Error("TunDeviceTest_Write_LargePacket: BringUp failed"); return false; }

    UDPSocket udp;
    if (!udp.Open())           { Logger::Error("TunDeviceTest_Write_LargePacket: UDPSocket Open failed"); return false; }
    if (!udp.Bind(kTunIP, 0))  { Logger::Error("TunDeviceTest_Write_LargePacket: UDPSocket Bind failed"); return false; }
    if (!udp.SetNonBlocking()) { Logger::Error("TunDeviceTest_Write_LargePacket: UDPSocket SetNonBlocking failed"); return false; }

    const uint16_t dst_port = udp.GetLocalEndpoint().value().port;

    EventPoller poller;
    if (!poller.Open())                                       { Logger::Error("TunDeviceTest_Write_LargePacket: poller Open failed"); return false; }
    if (!poller.Add(udp.GetHandle(), EventMask::Readable))    { Logger::Error("TunDeviceTest_Write_LargePacket: poller Add failed"); return false; }

    std::vector<uint8_t> big(1400);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i & 0xFF);

    auto pkt = TunDevice::BuildUdpPacket(kTunDst, kTunIP, 9998, dst_port, big);
    BytesTransferred written = dev.Write(pkt);
    if (written != static_cast<BytesTransferred>(pkt.size())) {
        Logger::Error("TunDeviceTest_Write_LargePacket: Write returned " + std::to_string(written));
        return false;
    }

    std::array<PollEvent, 2> events{};
    if (poller.Poll(events, 2000) < 1) {
        Logger::Error("TunDeviceTest_Write_LargePacket: UDP socket not readable within 2s");
        return false;
    }

    std::vector<uint8_t> recv_buf(2048);
    auto result = udp.ReceiveFrom(recv_buf);
    if (!result) { Logger::Error("TunDeviceTest_Write_LargePacket: ReceiveFrom returned nullopt"); return false; }
    if (result->bytes_read != big.size()) {
        Logger::Error("TunDeviceTest_Write_LargePacket: received " + std::to_string(result->bytes_read)
                      + " bytes, expected " + std::to_string(big.size()));
        return false;
    }
    if (memcmp(recv_buf.data(), big.data(), big.size()) != 0) {
        Logger::Error("TunDeviceTest_Write_LargePacket: payload mismatch");
        return false;
    }

    return true;
}

// =============================================================================
// Test 10: EventPoller integration
//
// Confirms TUN fd integrates correctly with the event loop:
//   - No spurious readable event before any traffic
//   - Outbound packet routed via tun_vpntest0 triggers a Readable event
//   - Draining the fd suppresses further events (level-triggered)
// =============================================================================
bool TunDeviceTest_EventPoller_Integration() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_EventPoller: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))  { Logger::Error("TunDeviceTest_EventPoller: Open failed"); return false; }
    if (!dev.SetNonBlocking()) { Logger::Error("TunDeviceTest_EventPoller: SetNonBlocking failed"); return false; }
    if (!dev.BringUp(kTunIP))  { Logger::Error("TunDeviceTest_EventPoller: BringUp failed"); return false; }

    // Drain kernel-generated packets (IGMP membership reports) placed on TUN fd during BringUp
    {
        std::vector<uint8_t> drain(4096);
        while (dev.Read(drain) > 0) {}
    }

    EventPoller poller;
    if (!poller.Open())                                       { Logger::Error("TunDeviceTest_EventPoller: poller Open failed"); return false; }
    if (!poller.Add(dev.GetHandle(), EventMask::Readable))    { Logger::Error("TunDeviceTest_EventPoller: Add failed"); return false; }

    // No traffic yet — must time out with 0 events
    std::array<PollEvent, 4> events{};
    int count = poller.Poll(events, 50);
    if (count != 0) { Logger::Error("TunDeviceTest_EventPoller: expected 0 events before traffic, got " + std::to_string(count)); return false; }

    // Send to kTunDst — routes via tun_vpntest0, making TUN fd readable
    UDPSocket udp;
    if (!udp.Open())          { Logger::Error("TunDeviceTest_EventPoller: UDPSocket Open failed"); return false; }
    if (!udp.Bind(kTunIP, 0)) { Logger::Error("TunDeviceTest_EventPoller: UDPSocket Bind failed"); return false; }

    std::array<uint8_t, 2> payload{0xAA, 0xBB};
    udp.SendTo({kTunDst, 9999}, payload);

    // EventPoller must fire Readable on the TUN fd
    count = poller.Poll(events, 3000);
    if (count < 1) { Logger::Error("TunDeviceTest_EventPoller: expected Readable after traffic, got " + std::to_string(count)); return false; }

    bool found = false;
    for (int i = 0; i < count; ++i) {
        if (events[static_cast<std::size_t>(i)].handle == dev.GetHandle() && events[static_cast<std::size_t>(i)].IsReadable()) { found = true; break; }
    }
    if (!found) { Logger::Error("TunDeviceTest_EventPoller: Readable event for TUN handle not found"); return false; }

    // Drain — next Poll must return 0 (level-triggered: empty buffer → no event)
    std::vector<uint8_t> drain(4096);
    dev.Read(drain);

    count = poller.Poll(events, 50);
    if (count != 0) { Logger::Error("TunDeviceTest_EventPoller: expected 0 events after drain, got " + std::to_string(count)); return false; }

    return true;
}

// =============================================================================
// Test 11: Operations on a closed device — all fail gracefully, no crash
// =============================================================================
bool TunDeviceTest_OperationsOnClosed() {
    if (!TunTest_IsPrivileged()) return false;

    TunDevice dev; // never opened

    Logger::Info("TunDeviceTest_OperationsOnClosed: === Expecting error logs below (intentional) ===");

    std::vector<uint8_t> buf(64, 0);
    if (dev.Read(buf) >= 0)   { Logger::Error("TunDeviceTest_OperationsOnClosed: Read on closed should return -1"); return false; }
    if (dev.Write(buf) >= 0)  { Logger::Error("TunDeviceTest_OperationsOnClosed: Write on closed should return -1"); return false; }
    if (dev.SetNonBlocking()) { Logger::Error("TunDeviceTest_OperationsOnClosed: SetNonBlocking on closed should return false"); return false; }
    if (dev.BringUp(kTunIP))  { Logger::Error("TunDeviceTest_OperationsOnClosed: BringUp on closed should return false"); return false; }

    Logger::Info("TunDeviceTest_OperationsOnClosed: === All operations correctly rejected ===");
    return true;
}

// =============================================================================
// Test 12: Burst inbound — 100 packets injected back-to-back, all delivered
//
// Verifies the kernel's TUN receive queue and UDP socket buffer handle a burst
// without dropping packets — important when a VPN server handles many clients.
// =============================================================================
bool TunDeviceTest_BurstInbound() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_BurstInbound: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface)) { Logger::Error("TunDeviceTest_BurstInbound: Open failed"); return false; }
    if (!dev.BringUp(kTunIP)) { Logger::Error("TunDeviceTest_BurstInbound: BringUp failed"); return false; }

    UDPSocket udp;
    if (!udp.Open() || !udp.Bind(kTunIP, 0) || !udp.SetNonBlocking()) {
        Logger::Error("TunDeviceTest_BurstInbound: socket setup failed");
        return false;
    }
    const uint16_t dst_port = udp.GetLocalEndpoint().value().port;

    EventPoller poller;
    if (!poller.Open() || !poller.Add(udp.GetHandle(), EventMask::Readable)) {
        Logger::Error("TunDeviceTest_BurstInbound: poller setup failed");
        return false;
    }

    static constexpr int kCount = 100;

    for (int i = 0; i < kCount; ++i) {
        std::array<uint8_t, 2> payload{static_cast<uint8_t>(i >> 8), static_cast<uint8_t>(i)};
        auto pkt = TunDevice::BuildUdpPacket(kTunDst, kTunIP, 9995, dst_port, payload);
        dev.Write(pkt);
    }

    std::vector<uint8_t> buf(256);
    int received = 0;
    while (received < kCount) {
        std::array<PollEvent, 2> ev{};
        if (poller.Poll(ev, 3000) < 1) {
            Logger::Error("TunDeviceTest_BurstInbound: timed out at "
                          + std::to_string(received) + "/" + std::to_string(kCount));
            return false;
        }
        while (udp.ReceiveFrom(buf)) ++received;
    }

    Logger::Info("TunDeviceTest_BurstInbound: " + std::to_string(received) + "/" + std::to_string(kCount) + " packets delivered");
    return true;
}

// =============================================================================
// Test 13: Multiple destination ports — packets routed to the correct socket
//
// Simulates multiple local applications (3 different ports) receiving traffic
// from the same VPN peer (kTunDst).  Each socket must receive exactly its share.
// =============================================================================
bool TunDeviceTest_MultiDestinationPorts() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_MultiDestinationPorts: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface)) { Logger::Error("TunDeviceTest_MultiDestinationPorts: Open failed"); return false; }
    if (!dev.BringUp(kTunIP)) { Logger::Error("TunDeviceTest_MultiDestinationPorts: BringUp failed"); return false; }

    static constexpr int kSockets   = 3;
    static constexpr int kPerSocket = 20;
    static constexpr int kTotal     = kSockets * kPerSocket;

    std::array<UDPSocket, kSockets> socks{};
    std::array<uint16_t,  kSockets> ports{};

    for (int s = 0; s < kSockets; ++s) {
        if (!socks[static_cast<std::size_t>(s)].Open()
         || !socks[static_cast<std::size_t>(s)].Bind(kTunIP, 0)
         || !socks[static_cast<std::size_t>(s)].SetNonBlocking()) {
            Logger::Error("TunDeviceTest_MultiDestinationPorts: socket " + std::to_string(s) + " setup failed");
            return false;
        }
        ports[static_cast<std::size_t>(s)] = socks[static_cast<std::size_t>(s)].GetLocalEndpoint().value().port;
    }

    for (int s = 0; s < kSockets; ++s) {
        for (int i = 0; i < kPerSocket; ++i) {
            std::array<uint8_t, 2> payload{static_cast<uint8_t>(s), static_cast<uint8_t>(i)};
            auto pkt = TunDevice::BuildUdpPacket(kTunDst, kTunIP, 9994, ports[static_cast<std::size_t>(s)], payload);
            dev.Write(pkt);
        }
    }

    EventPoller poller;
    if (!poller.Open()) { Logger::Error("TunDeviceTest_MultiDestinationPorts: poller Open failed"); return false; }
    for (int s = 0; s < kSockets; ++s) {
        if (!poller.Add(socks[static_cast<std::size_t>(s)].GetHandle(), EventMask::Readable)) {
            Logger::Error("TunDeviceTest_MultiDestinationPorts: poller Add " + std::to_string(s) + " failed");
            return false;
        }
    }

    std::array<int, kSockets> counts{};
    int total = 0;
    std::vector<uint8_t> buf(256);

    while (total < kTotal) {
        std::array<PollEvent, kSockets + 1> ev{};
        if (poller.Poll(ev, 3000) < 1) {
            Logger::Error("TunDeviceTest_MultiDestinationPorts: timed out at "
                          + std::to_string(total) + "/" + std::to_string(kTotal));
            return false;
        }
        for (int s = 0; s < kSockets; ++s) {
            while (socks[static_cast<std::size_t>(s)].ReceiveFrom(buf)) {
                ++counts[static_cast<std::size_t>(s)];
                ++total;
            }
        }
    }

    for (int s = 0; s < kSockets; ++s) {
        if (counts[static_cast<std::size_t>(s)] != kPerSocket) {
            Logger::Error("TunDeviceTest_MultiDestinationPorts: socket " + std::to_string(s)
                          + " got " + std::to_string(counts[static_cast<std::size_t>(s)])
                          + ", expected " + std::to_string(kPerSocket));
            return false;
        }
    }

    Logger::Info("TunDeviceTest_MultiDestinationPorts: " + std::to_string(total)
                 + " packets correctly routed to " + std::to_string(kSockets) + " sockets");
    return true;
}

// =============================================================================
// Test 14: Parallel injection — 4 threads each inject 25 packets concurrently
//
// Simulates multiple VPN worker threads pushing decrypted packets into the TUN
// simultaneously.  All 100 packets must arrive at the receiving socket.
// =============================================================================
bool TunDeviceTest_Multithread_ParallelInject() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_Multithread_ParallelInject: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface)) { Logger::Error("TunDeviceTest_Multithread_ParallelInject: Open failed"); return false; }
    if (!dev.BringUp(kTunIP)) { Logger::Error("TunDeviceTest_Multithread_ParallelInject: BringUp failed"); return false; }

    UDPSocket udp;
    if (!udp.Open() || !udp.Bind(kTunIP, 0) || !udp.SetNonBlocking()) {
        Logger::Error("TunDeviceTest_Multithread_ParallelInject: socket setup failed");
        return false;
    }
    const uint16_t dst_port = udp.GetLocalEndpoint().value().port;

    EventPoller poller;
    if (!poller.Open() || !poller.Add(udp.GetHandle(), EventMask::Readable)) {
        Logger::Error("TunDeviceTest_Multithread_ParallelInject: poller setup failed");
        return false;
    }

    static constexpr int kThreads   = 4;
    static constexpr int kPerThread = 25;
    static constexpr int kTotal     = kThreads * kPerThread;

    std::atomic<int> write_errors{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&dev, &write_errors, dst_port, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                std::array<uint8_t, 3> payload{
                    static_cast<uint8_t>(t),
                    static_cast<uint8_t>(i),
                    0xCC
                };
                auto pkt = TunDevice::BuildUdpPacket(
                    kTunDst, kTunIP,
                    static_cast<uint16_t>(9990 + t),
                    dst_port, payload);
                if (dev.Write(pkt) != static_cast<BytesTransferred>(pkt.size()))
                    ++write_errors;
            }
        });
    }

    for (auto& w : workers) w.join();

    if (write_errors > 0) {
        Logger::Error("TunDeviceTest_Multithread_ParallelInject: "
                      + std::to_string(write_errors.load()) + " write errors");
        return false;
    }

    std::vector<uint8_t> buf(256);
    int received = 0;
    while (received < kTotal) {
        std::array<PollEvent, 2> ev{};
        if (poller.Poll(ev, 5000) < 1) {
            Logger::Error("TunDeviceTest_Multithread_ParallelInject: timed out at "
                          + std::to_string(received) + "/" + std::to_string(kTotal));
            return false;
        }
        while (udp.ReceiveFrom(buf)) ++received;
    }

    Logger::Info("TunDeviceTest_Multithread_ParallelInject: "
                 + std::to_string(received) + " packets from "
                 + std::to_string(kThreads) + " concurrent threads");
    return true;
}

// =============================================================================
// Test 15: Concurrent bidirectional — inbound injection and outbound capture simultaneously
//
// Thread A injects kN packets inbound (Write → delivered to recv_sock).
// Thread B sends kN packets outbound (send_sock → TUN fd readable).
// Main thread drives the event loop and counts both directions.
// Models the full VPN data path under concurrent load.
// =============================================================================
bool TunDeviceTest_Multithread_Bidirectional() {
    if (!TunTest_IsPrivileged()) return false;
    if (TunDevice::Exists(kTunIface)) { Logger::Error("TunDeviceTest_Multithread_Bidirectional: interface pre-exists"); return false; }

    TunDevice dev;
    if (!dev.Open(kTunIface))  { Logger::Error("TunDeviceTest_Multithread_Bidirectional: Open failed"); return false; }
    if (!dev.SetNonBlocking()) { Logger::Error("TunDeviceTest_Multithread_Bidirectional: SetNonBlocking failed"); return false; }
    if (!dev.BringUp(kTunIP))  { Logger::Error("TunDeviceTest_Multithread_Bidirectional: BringUp failed"); return false; }

    { std::vector<uint8_t> drain(4096); while (dev.Read(drain) > 0) {} }

    // recv_sock — receives inbound packets injected by Thread A
    UDPSocket recv_sock;
    if (!recv_sock.Open() || !recv_sock.Bind(kTunIP, 0) || !recv_sock.SetNonBlocking()) {
        Logger::Error("TunDeviceTest_Multithread_Bidirectional: recv_sock setup failed");
        return false;
    }
    const uint16_t recv_port = recv_sock.GetLocalEndpoint().value().port;

    // send_sock — sends outbound packets that TUN fd captures
    UDPSocket send_sock;
    if (!send_sock.Open() || !send_sock.Bind(kTunIP, 0)) {
        Logger::Error("TunDeviceTest_Multithread_Bidirectional: send_sock setup failed");
        return false;
    }

    EventPoller poller;
    if (!poller.Open()
     || !poller.Add(recv_sock.GetHandle(), EventMask::Readable)
     || !poller.Add(dev.GetHandle(),       EventMask::Readable)) {
        Logger::Error("TunDeviceTest_Multithread_Bidirectional: poller setup failed");
        return false;
    }

    static constexpr int kN = 50;

    std::thread injector([&dev, recv_port]() {
        for (int i = 0; i < kN; ++i) {
            std::array<uint8_t, 1> payload{static_cast<uint8_t>(i)};
            auto pkt = TunDevice::BuildUdpPacket(kTunDst, kTunIP, 9989, recv_port, payload);
            dev.Write(pkt);
        }
    });

    std::thread sender([&send_sock]() {
        for (int i = 0; i < kN; ++i) {
            std::array<uint8_t, 1> payload{static_cast<uint8_t>(i)};
            send_sock.SendTo({kTunDst, 9988}, payload);
        }
    });

    std::vector<uint8_t> buf(4096);
    int inbound = 0, outbound = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while ((inbound < kN || outbound < kN) && std::chrono::steady_clock::now() < deadline) {
        std::array<PollEvent, 4> ev{};
        int n = poller.Poll(ev, 1000);
        for (int i = 0; i < n; ++i) {
            if (ev[static_cast<std::size_t>(i)].handle == recv_sock.GetHandle())
                while (recv_sock.ReceiveFrom(buf)) ++inbound;
            if (ev[static_cast<std::size_t>(i)].handle == dev.GetHandle())
                while (dev.Read(buf) > 0) ++outbound;
        }
    }

    injector.join();
    sender.join();

    if (inbound != kN || outbound != kN) {
        Logger::Error("TunDeviceTest_Multithread_Bidirectional: inbound="
                      + std::to_string(inbound) + " outbound="
                      + std::to_string(outbound) + " expected=" + std::to_string(kN));
        return false;
    }

    Logger::Info("TunDeviceTest_Multithread_Bidirectional: "
                 + std::to_string(inbound) + " inbound + "
                 + std::to_string(outbound) + " outbound");
    return true;
}

#endif // _PQVPN_TESTS_TUN_DEVICE_TESTS_HPP_
