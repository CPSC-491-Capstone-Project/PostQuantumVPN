#ifndef _PQVPN_TESTS_EVENT_POLLER_TESTS_HPP_
#define _PQVPN_TESTS_EVENT_POLLER_TESTS_HPP_

#include "test_utils.hpp"
#include "event_poller.hpp"
#include "udp_socket.hpp"
#include "logger.hpp"

#include <array>
#include <vector>
#include <cstring>

using namespace core::network;
using core::utils::Logger;

static std::uint16_t BoundPortEP(const UDPSocket& sock) {
    auto ep = sock.GetLocalEndpoint();
    return ep ? ep->port : 0;
}

// =============================================================================
// Test 1: Full lifecycle: Open, Add, Poll readable, Modify to writable,
//         Poll writable, Remove, Close. Two UDP sockets talking through
//         a single poller. Exercises every EventPoller method.
// =============================================================================
bool EventPollerTest_FullLifecycle() {

    // Setup: two non-blocking loopback UDP sockets
    UDPSocket sock_a;
    UDPSocket sock_b;

    if (!sock_a.Open())                     { Logger::Error("EPTest1: sock_a Open failed"); return false; }
    if (!sock_a.Bind("127.0.0.1", 0))       { Logger::Error("EPTest1: sock_a Bind failed"); return false; }
    if (!sock_a.SetNonBlocking())           { Logger::Error("EPTest1: sock_a SetNonBlocking failed"); return false; }

    if (!sock_b.Open())                     { Logger::Error("EPTest1: sock_b Open failed"); return false; }
    if (!sock_b.Bind("127.0.0.1", 0))       { Logger::Error("EPTest1: sock_b Bind failed"); return false; }
    if (!sock_b.SetNonBlocking())           { Logger::Error("EPTest1: sock_b SetNonBlocking failed"); return false; }

    const Handle handle_a = sock_a.GetHandle();
    const Handle handle_b = sock_b.GetHandle();
    const std::uint16_t port_a = BoundPortEP(sock_a);
    const std::uint16_t port_b = BoundPortEP(sock_b);

    if (port_a == 0 || port_b == 0) { Logger::Error("EPTest1: ephemeral port is 0"); return false; }

    // 1. Open the poller
    EventPoller poller;
    if (!poller.Open())   { Logger::Error("EPTest1: poller Open failed"); return false; }
    if (!poller.IsOpen()) { Logger::Error("EPTest1: poller not open after Open()"); return false; }
    if (poller.GetHandle() == kInvalidHandle) { Logger::Error("EPTest1: poller handle invalid"); return false; }

    // 2. Add both sockets for Readable
    if (!poller.Add(handle_a, EventMask::Readable)) { Logger::Error("EPTest1: Add handle_a failed"); return false; }
    if (!poller.Add(handle_b, EventMask::Readable)) { Logger::Error("EPTest1: Add handle_b failed"); return false; }

    // 3. Poll with no data — should timeout with 0 events
    std::array<PollEvent, 4> events{};
    int count = poller.Poll(events, /*timeout_ms=*/50);
    if (count != 0) { Logger::Error("EPTest1: expected 0 events on empty poll, got " + std::to_string(count)); return false; }

    // 4. Send data A -> B, poll for readable on B
    std::vector<std::uint8_t> payload = {0xCA, 0xFE, 0xBA, 0xBE};
    BytesTransferred sent = sock_a.SendTo({"127.0.0.1", port_b}, payload);
    if (sent != 4) { Logger::Error("EPTest1: SendTo A->B failed"); return false; }

    count = poller.Poll(events, /*timeout_ms=*/500);
    if (count < 1) { Logger::Error("EPTest1: expected readable event on sock_b, got " + std::to_string(count)); return false; }

    // Find the event for handle_b
    bool found_b_readable = false;
    for (auto i{0uz}; i < static_cast<std::size_t>(count); ++i) {
        if (events[i].handle == handle_b && events[i].IsReadable()) {
            found_b_readable = true;
            break;
        }
    }
    if (!found_b_readable) { Logger::Error("EPTest1: handle_b readable event not found"); return false; }

    // 5. Read the data from sock_b
    std::vector<std::uint8_t> recv_buf(64);
    auto result = sock_b.ReceiveFrom(recv_buf);
    if (!result) { Logger::Error("EPTest1: ReceiveFrom sock_b failed"); return false; }
    if (result->bytes_read != 4) { Logger::Error("EPTest1: expected 4 bytes, got " + std::to_string(result->bytes_read)); return false; }
    if (std::memcmp(recv_buf.data(), payload.data(), 4) != 0) { Logger::Error("EPTest1: payload mismatch"); return false; }

    // 6. Modify sock_b to also watch Writable
    if (!poller.Modify(handle_b, EventMask::Readable | EventMask::Writable)) {
        Logger::Error("EPTest1: Modify handle_b failed");
        return false;
    }

    // A UDP socket is (almost) always writable, so poll should fire immediately
    count = poller.Poll(events, /*timeout_ms=*/100);
    if (count < 1) { Logger::Error("EPTest1: expected writable event after Modify, got " + std::to_string(count)); return false; }

    bool found_b_writable = false;
    for (auto i{0uz}; i < static_cast<std::size_t>(count); ++i) {
        if (events[i].handle == handle_b && events[i].IsWritable()) {
            found_b_writable = true;
            break;
        }
    }
    if (!found_b_writable) { Logger::Error("EPTest1: handle_b writable event not found"); return false; }

    // 7. Send reply B -> A using the writable event
    std::vector<std::uint8_t> reply = {0xDE, 0xAD};
    sent = sock_b.SendTo({"127.0.0.1", port_a}, reply);
    if (sent != 2) { Logger::Error("EPTest1: SendTo B->A failed"); return false; }

    // Modify back to Readable only (stop the writable spin)
    if (!poller.Modify(handle_b, EventMask::Readable)) {
        Logger::Error("EPTest1: Modify handle_b back to Readable failed");
        return false;
    }

    // 8. Poll for A's readable event
    count = poller.Poll(events, /*timeout_ms=*/500);
    if (count < 1) { Logger::Error("EPTest1: expected readable event on sock_a, got " + std::to_string(count)); return false; }

    bool found_a_readable = false;
    for (auto i{0uz}; i < static_cast<std::size_t>(count); ++i) {
        if (events[i].handle == handle_a && events[i].IsReadable()) {
            found_a_readable = true;
            break;
        }
    }
    if (!found_a_readable) { Logger::Error("EPTest1: handle_a readable event not found"); return false; }

    // Read and verify
    std::vector<std::uint8_t> reply_buf(64);
    auto reply_result = sock_a.ReceiveFrom(reply_buf);
    if (!reply_result) { Logger::Error("EPTest1: ReceiveFrom sock_a failed"); return false; }
    if (reply_result->bytes_read != 2) { Logger::Error("EPTest1: reply size mismatch"); return false; }
    if (std::memcmp(reply_buf.data(), reply.data(), 2) != 0) { Logger::Error("EPTest1: reply payload mismatch"); return false; }

    // 9. Remove both handles 
    if (!poller.Remove(handle_a)) { Logger::Error("EPTest1: Remove handle_a failed"); return false; }
    if (!poller.Remove(handle_b)) { Logger::Error("EPTest1: Remove handle_b failed"); return false; }

    // After removal, poll should return 0 even with data pending
    sock_a.SendTo({"127.0.0.1", port_b}, payload);
    count = poller.Poll(events, /*timeout_ms=*/50);
    if (count != 0) { Logger::Error("EPTest1: expected 0 events after Remove, got " + std::to_string(count)); return false; }

    // 10. Close and verify
    poller.Close();
    if (poller.IsOpen()) { Logger::Error("EPTest1: poller still open after Close()"); return false; }
    if (poller.GetHandle() != kInvalidHandle) { Logger::Error("EPTest1: handle not invalid after Close()"); return false; }

    return true;
}

// =============================================================================
// Test 2: Two independent pollers, move semantics, guard-rail behavior
//         (operations on closed poller, empty Poll span, etc.)
// =============================================================================
bool EventPollerTest_TwoPollersAndMoveSemantics() {

    //Setup: one socket pair, two pollers
    UDPSocket sock_a;
    UDPSocket sock_b;

    if (!sock_a.Open())                     { Logger::Error("EPTest2: sock_a Open failed"); return false; }
    if (!sock_a.Bind("127.0.0.1", 0))      { Logger::Error("EPTest2: sock_a Bind failed"); return false; }
    if (!sock_a.SetNonBlocking())           { Logger::Error("EPTest2: sock_a SetNonBlocking failed"); return false; }

    if (!sock_b.Open())                     { Logger::Error("EPTest2: sock_b Open failed"); return false; }
    if (!sock_b.Bind("127.0.0.1", 0))      { Logger::Error("EPTest2: sock_b Bind failed"); return false; }
    if (!sock_b.SetNonBlocking())           { Logger::Error("EPTest2: sock_b SetNonBlocking failed"); return false; }

    const Handle handle_a = sock_a.GetHandle();
    const Handle handle_b = sock_b.GetHandle();
    const std::uint16_t port_a = BoundPortEP(sock_a);
    const std::uint16_t port_b = BoundPortEP(sock_b);

    // 1. Each socket gets its own poller
    //    (Simulates client and server with independent loops)
    EventPoller poller_a;
    EventPoller poller_b;

    if (!poller_a.Open()) { Logger::Error("EPTest2: poller_a Open failed"); return false; }
    if (!poller_b.Open()) { Logger::Error("EPTest2: poller_b Open failed"); return false; }

    if (!poller_a.Add(handle_a, EventMask::Readable)) { Logger::Error("EPTest2: Add A to poller_a failed"); return false; }
    if (!poller_b.Add(handle_b, EventMask::Readable)) { Logger::Error("EPTest2: Add B to poller_b failed"); return false; }

    // 2. Move-construct poller_a into poller_c
    //    poller_a should become invalid, poller_c takes ownership
    const Handle original_a_handle = poller_a.GetHandle();
    EventPoller poller_c{std::move(poller_a)};

    if (poller_a.IsOpen()) { Logger::Error("EPTest2: poller_a still open after move"); return false; }
    if (!poller_c.IsOpen()) { Logger::Error("EPTest2: poller_c not open after move-construct"); return false; }
    if (poller_c.GetHandle() != original_a_handle) { Logger::Error("EPTest2: poller_c handle mismatch after move"); return false; }

    // 3. Verify poller_c still works: send data and poll
    std::vector<std::uint8_t> msg1 = {0x01, 0x02, 0x03};
    sock_b.SendTo({"127.0.0.1", port_a}, msg1);

    std::array<PollEvent, 4> events{};
    int count = poller_c.Poll(events, /*timeout_ms=*/500);
    if (count < 1) { Logger::Error("EPTest2: poller_c poll failed after move-construct"); return false; }
    if (events[0].handle != handle_a) { Logger::Error("EPTest2: wrong handle from poller_c"); return false; }
    if (!events[0].IsReadable()) { Logger::Error("EPTest2: expected readable from poller_c"); return false; }

    // Drain the data
    std::vector<std::uint8_t> buf(64);
    sock_a.ReceiveFrom(buf);

    // 4. Move-assign poller_b into poller_c
    //    This should close poller_c's old epoll fd and take poller_b's
    const Handle original_b_handle = poller_b.GetHandle();
    poller_c = std::move(poller_b);

    if (poller_b.IsOpen()) { Logger::Error("EPTest2: poller_b still open after move-assign"); return false; }
    if (!poller_c.IsOpen()) { Logger::Error("EPTest2: poller_c not open after move-assign"); return false; }
    if (poller_c.GetHandle() != original_b_handle) { Logger::Error("EPTest2: poller_c handle mismatch after move-assign"); return false; }

    // 5. Verify poller_c now monitors sock_b (not sock_a)
    std::vector<std::uint8_t> msg2 = {0xAA, 0xBB};
    sock_a.SendTo({"127.0.0.1", port_b}, msg2);

    count = poller_c.Poll(events, /*timeout_ms=*/500);
    if (count < 1) { Logger::Error("EPTest2: poller_c poll failed after move-assign"); return false; }
    if (events[0].handle != handle_b) { Logger::Error("EPTest2: expected handle_b from poller_c after move-assign"); return false; }

    // Drain
    sock_b.ReceiveFrom(buf);

    // 6. Guard-rail: operations on closed/moved-from poller
    //    poller_a and poller_b were moved from — they should reject operations
    if (poller_a.Add(handle_a, EventMask::Readable)) { Logger::Error("EPTest2: Add on moved-from poller_a should fail"); return false; }
    if (poller_a.Modify(handle_a, EventMask::Writable)) { Logger::Error("EPTest2: Modify on moved-from should fail"); return false; }
    if (poller_a.Remove(handle_a)) { Logger::Error("EPTest2: Remove on moved-from should fail"); return false; }

    int poll_result = poller_a.Poll(events, 0);
    if (poll_result != -1) { Logger::Error("EPTest2: Poll on moved-from should return -1"); return false; }

    // 7. Guard-rail: empty span to Poll
    std::span<PollEvent> empty_span{};
    count = poller_c.Poll(empty_span, 0);
    if (count != 0) { Logger::Error("EPTest2: empty span Poll should return 0, got " + std::to_string(count)); return false; }

    // 8. Teardown
    poller_c.Remove(handle_b);
    poller_c.Close();

    if (poller_c.IsOpen()) { Logger::Error("EPTest2: poller_c still open after Close"); return false; }

    return true;
}

// =============================================================================
// Test 3: Operations on a closed poller should all fail gracefully.
//         This test PASSES when every operation correctly rejects.
//         Check the log output to verify Logger::Error fires for each.
// =============================================================================
bool EventPollerTest_OperationsOnClosedPoller() {

    UDPSocket sock;
    if (!sock.Open())                   { Logger::Error("event_poller_test: sock Open failed"); return false; }
    if (!sock.Bind("127.0.0.1", 0))    { Logger::Error("event_poller_test: sock Bind failed"); return false; }

    const Handle sock_handle = sock.GetHandle();

    // Open a poller, then immediately close it
    EventPoller poller;
    if (!poller.Open()) { Logger::Error("event_poller_test: poller Open failed"); return false; }
    poller.Close();

    // Every operation below should fail and produce a Logger::Error line.
    // If any of them succeed, something is wrong.

    Logger::Info("event_poller_test: === Expecting error logs below and this is intentional ===");

    if (poller.Add(sock_handle, EventMask::Readable)) {
        Logger::Error("event_poller_test: Add succeeded on closed poller");
        return false;
    }

    if (poller.Modify(sock_handle, EventMask::Writable)) {
        Logger::Error("event_poller_test: Modify succeeded on closed poller");
        return false;
    }

    if (poller.Remove(sock_handle)) {
        Logger::Error("event_poller_test: Remove succeeded on closed poller");
        return false;
    }

    std::array<PollEvent, 4> events{};
    int count = poller.Poll(events, 0);
    if (count != -1) {
        Logger::Error("event_poller_test: Poll returned " + std::to_string(count) + " instead of -1");
        return false;
    }

    Logger::Info("event_poller_test: === All operations correctly rejected ===");

    return true;
}
#endif // _PQVPN_TESTS_EVENT_POLLER_TESTS_HPP_
