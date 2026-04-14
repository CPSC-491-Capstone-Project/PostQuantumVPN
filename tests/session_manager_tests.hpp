#ifndef _PQVPN_TESTS_SESSION_MANAGER_TESTS_HPP_
#define _PQVPN_TESTS_SESSION_MANAGER_TESTS_HPP_

#include "test_utils.hpp"
#include "session_manager.hpp"
#include "ipv4.hpp"

using core::session::Session;
using core::session::SessionManager;
using core::session::SessionSecrets;

// ============================================================================
// Helpers
// ============================================================================

static SessionSecrets MakeSecrets(std::uint8_t pattern,
                                  std::uint32_t sender,
                                  std::uint32_t receiver,
                                  bool initiator = true) {
    SessionSecrets s;
    s.send_key.fill(pattern);
    s.recv_key.fill(static_cast<std::uint8_t>(pattern + 1));
    s.sender_index   = sender;
    s.receiver_index = receiver;
    s.is_initiator   = initiator;
    return s;
}

static core::network::Endpoint MakeEndpoint(std::uint16_t port = 51820) {
    return core::network::Endpoint{core::network::IPv4(127, 0, 0, 1), port};
}

// ============================================================================
// Tests
// ============================================================================

// Create a session from mock SessionSecrets — verify it is findable by index
bool SessionManagerTest_ActivateSession_FindableByIndex() {
    SessionManager mgr;
    auto secrets = MakeSecrets(0xAB, 1001, 2001);

    Session* s = mgr.ActivateSession(secrets, MakeEndpoint());
    if (!s) return test_helper("non-null", "nullptr");

    Session* found = mgr.Lookup(1001);
    return test_helper("1", std::to_string(found == s));
}

// The session's send/recv keys must match exactly what was provided
bool SessionManagerTest_ActivateSession_KeysMatch() {
    SessionManager mgr;
    auto secrets = MakeSecrets(0x42, 1002, 2002);

    Session* s = mgr.ActivateSession(secrets, MakeEndpoint());
    if (!s) return test_helper("non-null", "nullptr");

    bool send_match = (s->send_key == secrets.send_key);
    bool recv_match = (s->recv_key == secrets.recv_key);
    bool idx_match  = (s->sender_index == 1002) && (s->receiver_index == 2002);

    return test_helper("1", std::to_string(send_match && recv_match && idx_match));
}

// All-zero send key is rejected — defensive check against a failed handshake
bool SessionManagerTest_ActivateSession_ZeroKeyRejected() {
    SessionManager mgr;
    SessionSecrets zero_secrets;  // default-initialized: all fields zero

    Session* s = mgr.ActivateSession(zero_secrets, MakeEndpoint());
    return test_helper("1", std::to_string(s == nullptr));
}

// TransitionSession: new session is active, old session is removed
bool SessionManagerTest_TransitionSession_OldRemovedNewActive() {
    SessionManager mgr;

    Session* old_s = mgr.ActivateSession(MakeSecrets(0x11, 100, 200), MakeEndpoint());
    if (!old_s) return test_helper("old session", "nullptr");

    Session* new_s = mgr.TransitionSession(100, MakeSecrets(0x22, 101, 201), MakeEndpoint());
    if (!new_s) return test_helper("new session", "nullptr");

    bool old_gone = (mgr.Lookup(100) == nullptr);
    bool new_present = (mgr.Lookup(101) == new_s);

    return test_helper("1", std::to_string(old_gone && new_present));
}

// TransitionSession failure: if new secrets are invalid, old session remains active
bool SessionManagerTest_TransitionSession_FailureKeepsOldSession() {
    SessionManager mgr;

    Session* old_s = mgr.ActivateSession(MakeSecrets(0x55, 200, 300), MakeEndpoint());
    if (!old_s) return test_helper("old session", "nullptr");

    SessionSecrets bad_secrets;  // all-zero keys — will be rejected
    Session* new_s = mgr.TransitionSession(200, bad_secrets, MakeEndpoint());

    bool new_failed    = (new_s == nullptr);
    bool old_still_active = (mgr.Lookup(200) == old_s);

    return test_helper("1", std::to_string(new_failed && old_still_active));
}

#endif // _PQVPN_TESTS_SESSION_MANAGER_TESTS_HPP_
