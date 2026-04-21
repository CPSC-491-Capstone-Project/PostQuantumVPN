#ifndef _PQVPN_TESTS_SESSION_LIFECYCLE_TESTS_HPP_
#define _PQVPN_TESTS_SESSION_LIFECYCLE_TESTS_HPP_

#include "test_utils.hpp"
#include "handshake_constants.hpp"
#include "session.hpp"
#include "session_manager.hpp"
#include "ipv4.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using core::session::Session;
using core::session::SessionManager;
using core::session::SessionSecrets;

namespace cc = core::cryptography::chacha20_poly1305;

// ============================================================================
// Helpers
// ============================================================================

static cc::Key SlTest_MakeKey(std::uint8_t pattern) {
    cc::Key k; k.fill(pattern); return k;
}

static std::unique_ptr<Session> SlTest_MakeSession(
    std::uint32_t sender_index = 100,
    std::uint32_t receiver_index = 200)
{
    auto s = std::make_unique<Session>();
    s->send_key       = SlTest_MakeKey(0xAA);
    s->recv_key       = SlTest_MakeKey(0xBB);
    s->sender_index   = sender_index;
    s->receiver_index = receiver_index;
    s->created        = std::chrono::system_clock::now();
    s->rekey_jitter   = std::chrono::milliseconds{0};
    return s;
}

static SessionSecrets SlTest_MakeSecrets(
    std::uint32_t sender_index   = 100,
    std::uint32_t receiver_index = 200)
{
    SessionSecrets sc{};
    sc.send_key       = SlTest_MakeKey(0xAA);
    sc.recv_key       = SlTest_MakeKey(0xBB);
    sc.sender_index   = sender_index;
    sc.receiver_index = receiver_index;
    return sc;
}

static core::network::Endpoint SlTest_MakeEndpoint() {
    return core::network::Endpoint{core::network::IPv4(127, 0, 0, 1), 51820};
}

// ============================================================================
// IsExpired
// ============================================================================

bool SessionLifecycleTest_IsExpired_FreshSession() {
    auto s = SlTest_MakeSession();
    return test_helper("0", std::to_string(s->IsExpired()));
}

bool SessionLifecycleTest_IsExpired_ExpiredSession() {
    auto s = SlTest_MakeSession();
    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRejectAfterTime
                 - std::chrono::seconds{1};
    return test_helper("1", std::to_string(s->IsExpired()));
}

bool SessionLifecycleTest_IsExpired_ExactBoundary() {
    auto s = SlTest_MakeSession();
    // One second before the threshold — should not be expired
    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRejectAfterTime
                 + std::chrono::seconds{1};
    return test_helper("0", std::to_string(s->IsExpired()));
}

// ============================================================================
// NeedsRekey
// ============================================================================

bool SessionLifecycleTest_NeedsRekey_FreshSession() {
    auto s = SlTest_MakeSession();
    return test_helper("0", std::to_string(s->NeedsRekey()));
}

bool SessionLifecycleTest_NeedsRekey_OldSession() {
    auto s = SlTest_MakeSession();
    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRekeyAfterTime
                 - std::chrono::seconds{1};
    return test_helper("1", std::to_string(s->NeedsRekey()));
}

bool SessionLifecycleTest_NeedsRekey_CounterAtThreshold() {
    auto s = SlTest_MakeSession();
    s->send_nonce.store(core::handshake::kRekeyAfterMessages);
    return test_helper("1", std::to_string(s->NeedsRekey()));
}

bool SessionLifecycleTest_NeedsRekey_FlagBlocks() {
    auto s = SlTest_MakeSession();
    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRekeyAfterTime
                 - std::chrono::seconds{1};
    s->rekey_requested.store(true);
    return test_helper("0", std::to_string(s->NeedsRekey()));
}

bool SessionLifecycleTest_NeedsRekey_JitterExtends() {
    auto s = SlTest_MakeSession();
    // Backdated to just past kRekeyAfterTime but within jitter range
    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRekeyAfterTime
                 - std::chrono::milliseconds{1};
    // With large jitter, session should NOT yet need rekey
    s->rekey_jitter = std::chrono::milliseconds{333};
    return test_helper("0", std::to_string(s->NeedsRekey()));
}

// ============================================================================
// CheckRekeys / SweepExpired
// ============================================================================

bool SessionLifecycleTest_CheckRekeys_NoSessions() {
    SessionManager mgr;
    const auto result = mgr.CheckRekeys();
    return test_helper("0", std::to_string(result.empty()));
}

bool SessionLifecycleTest_CheckRekeys_StaleSession() {
    SessionManager mgr;
    auto sc = SlTest_MakeSecrets(77, 88);
    auto* s = mgr.ActivateSession(sc, SlTest_MakeEndpoint());
    if (!s) return false;

    s->created     = std::chrono::system_clock::now()
                     - core::handshake::kRekeyAfterTime
                     - std::chrono::seconds{1};
    s->rekey_jitter = std::chrono::milliseconds{0};

    const auto result = mgr.CheckRekeys();
    const bool found  = std::find(result.begin(), result.end(), 77u) != result.end();
    return test_helper("1", std::to_string(found));
}

bool SessionLifecycleTest_CheckRekeys_FreshSessionExcluded() {
    SessionManager mgr;
    auto sc = SlTest_MakeSecrets(55, 66);
    mgr.ActivateSession(sc, SlTest_MakeEndpoint());

    const auto result = mgr.CheckRekeys();
    return test_helper("0", std::to_string(!result.empty()));
}

bool SessionLifecycleTest_SweepExpired_RemovesExpired() {
    SessionManager mgr;
    auto sc = SlTest_MakeSecrets(11, 22);
    auto* s = mgr.ActivateSession(sc, SlTest_MakeEndpoint());
    if (!s) return false;

    s->created = std::chrono::system_clock::now()
                 - core::handshake::kRejectAfterTime
                 - std::chrono::seconds{1};

    const std::size_t removed = mgr.SweepExpired();
    const bool gone           = mgr.Lookup(11) == nullptr;
    return test_helper("1", std::to_string(removed == 1 && gone));
}

bool SessionLifecycleTest_SweepExpired_KeepsFresh() {
    SessionManager mgr;
    auto sc = SlTest_MakeSecrets(33, 44);
    mgr.ActivateSession(sc, SlTest_MakeEndpoint());

    const std::size_t removed = mgr.SweepExpired();
    return test_helper("0", std::to_string(removed));
}

// ============================================================================
// ShouldSendKeepalive / CreateKeepalive / GetKeepaliveDue
// ============================================================================

bool SessionLifecycleTest_Keepalive_FreshSession_False() {
    auto s = SlTest_MakeSession();
    return test_helper("0", std::to_string(s->ShouldSendKeepalive()));
}

bool SessionLifecycleTest_Keepalive_NoInboundTraffic_False() {
    auto s = SlTest_MakeSession();
    // last_sent_time at epoch (nothing sent) but no received packets either
    return test_helper("0", std::to_string(s->ShouldSendKeepalive()));
}

bool SessionLifecycleTest_Keepalive_AfterReceive_IdleSend_True() {
    auto s = SlTest_MakeSession();
    // Simulate: received a packet, but last sent was > kKeepaliveTimeout ago
    s->last_received_time = std::chrono::steady_clock::now() - std::chrono::seconds{5};
    s->last_sent_time     = std::chrono::steady_clock::now()
                            - core::handshake::kKeepaliveTimeout
                            - std::chrono::seconds{1};
    return test_helper("1", std::to_string(s->ShouldSendKeepalive()));
}

bool SessionLifecycleTest_Keepalive_RecentSend_False() {
    auto s = SlTest_MakeSession();
    s->last_received_time = std::chrono::steady_clock::now() - std::chrono::seconds{5};
    s->last_sent_time     = std::chrono::steady_clock::now();
    return test_helper("0", std::to_string(s->ShouldSendKeepalive()));
}

bool SessionLifecycleTest_CreateKeepalive_Produces16Bytes() {
    auto s = SlTest_MakeSession();
    const auto out = s->CreateKeepalive();
    if (!out) return false;
    return test_helper("16", std::to_string(out->size()));
}

bool SessionLifecycleTest_CreateKeepalive_Roundtrip() {
    auto sender   = SlTest_MakeSession(100, 200);
    auto receiver = SlTest_MakeSession(200, 100);
    receiver->send_key = SlTest_MakeKey(0xBB);
    receiver->recv_key = SlTest_MakeKey(0xAA);

    const auto sealed = sender->CreateKeepalive();
    if (!sealed) return false;

    // counter is 0 (first call)
    const auto opened = receiver->Open(0, *sealed);
    if (!opened) return false;

    return test_helper("0", std::to_string(opened->size()));
}

bool SessionLifecycleTest_GetKeepaliveDue_NoSessions() {
    SessionManager mgr;
    return test_helper("0", std::to_string(mgr.GetKeepaliveDue().empty()));
}

bool SessionLifecycleTest_GetKeepaliveDue_DueSession() {
    SessionManager mgr;
    auto sc = SlTest_MakeSecrets(99, 88);
    auto* s = mgr.ActivateSession(sc, SlTest_MakeEndpoint());
    if (!s) return false;

    s->last_received_time = std::chrono::steady_clock::now() - std::chrono::seconds{5};
    s->last_sent_time     = std::chrono::steady_clock::now()
                            - core::handshake::kKeepaliveTimeout
                            - std::chrono::seconds{1};

    const auto result = mgr.GetKeepaliveDue();
    const bool found  = std::find(result.begin(), result.end(), 99u) != result.end();
    return test_helper("1", std::to_string(found));
}

#endif // _PQVPN_TESTS_SESSION_LIFECYCLE_TESTS_HPP_
