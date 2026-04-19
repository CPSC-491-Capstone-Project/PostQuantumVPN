#ifndef _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_
#define _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_

#include "session.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace core::session {

class SessionManager {
public:

    // Entry point called by the handshake module on completion (both initiator
    // and responder paths). Validates that keys are not all-zero, constructs
    // and registers the session, and logs it at Info level.
    // Returns nullptr if validation fails.
    Session* ActivateSession(SessionSecrets secrets, core::network::Endpoint peer);

    // Rekey path: creates a new session via ActivateSession, then removes the
    // old session only if the new one was successfully created. If creation
    // fails the old session remains active and a warning is logged.
    Session* TransitionSession(std::uint32_t old_sender_index,
                               SessionSecrets new_secrets,
                               core::network::Endpoint peer);

    // Returns the session for the given sender index, or nullptr if not found.
    Session* Lookup(std::uint32_t sender_index);

    // Removes the session for the given sender index (secure-zeroes keys on destruction).
    void Remove(std::uint32_t sender_index);

private:

    // Constructs a Session from secrets, inserts it into the table, and returns
    // a raw pointer. Caller must not hold mutex_ when calling this.
    Session* CreateSession(SessionSecrets secrets, core::network::Endpoint peer);

    std::unordered_map<std::uint32_t, std::unique_ptr<Session>> sessions_;
    std::mutex mutex_;
};

} // namespace core::session

#endif // _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_
