#ifndef _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_
#define _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_

#include "session.hpp"
#include "siphash.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

namespace core::session {

class SessionManager {
public:
    // Generates a random SipHash key for the internal hash table.
    SessionManager();

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
    // Takes a shared (read) lock — safe to call concurrently from the receive loop.
    Session* Lookup(std::uint32_t sender_index);

    // Removes the session for the given sender index (secure-zeroes keys on destruction).
    void Remove(std::uint32_t sender_index);

    // Generates a random, non-zero sender index that does not collide with any
    // currently active session. Extremely unlikely to loop in practice.
    std::uint32_t GenerateSenderIndex();

    // Returns the number of active sessions.
    std::size_t GetSessionCount();

private:
    // Constructs a Session from secrets, inserts it into the table, and returns
    // a raw pointer. Caller must not hold mutex_ when calling this.
    Session* CreateSession(SessionSecrets secrets, core::network::Endpoint peer);

    // Builds a SipHasher with a fresh random key. Called once in the constructor.
    static struct SipHasher MakeHasher();

    // SipHash24-keyed hasher for the session table.
    // Randomised at construction time to prevent hash-flooding DoS attacks where
    // an attacker crafts receiver_index values that all land in the same bucket.
    struct SipHasher {
        core::cryptography::siphash::Key key{};

        std::size_t operator()(std::uint32_t index) const noexcept {
            core::cryptography::siphash::SipHash24 hasher;
            std::array<std::uint8_t, 4> buf;
            std::memcpy(buf.data(), &index, sizeof(index));
            return static_cast<std::size_t>(hasher(key, buf));
        }
    };

    std::unordered_map<std::uint32_t, std::unique_ptr<Session>, SipHasher> sessions_;

    // shared_mutex: concurrent Lookup/GetSessionCount reads are allowed;
    // ActivateSession/Remove/GenerateSenderIndex take an exclusive write lock.
    mutable std::shared_mutex mutex_;
};

} // namespace core::session

#endif // _PQVPN_CORE_SESSION_SESSION_MANAGER_HPP_
