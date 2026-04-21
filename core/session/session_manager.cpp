#include "session_manager.hpp"
#include "logger.hpp"

#include <algorithm>
#include <openssl/rand.h>
#include <string>

using core::utils::Logger;

namespace core::session {

SessionManager::SessionManager() : sessions_(0, MakeHasher()) {}

struct SessionManager::SipHasher SessionManager::MakeHasher() {
    SipHasher h;
    RAND_bytes(h.key.data(), static_cast<int>(h.key.size()));
    return h;
}

Session* SessionManager::ActivateSession(SessionSecrets secrets, core::network::Endpoint peer) {
    const bool send_zero = std::all_of(secrets.send_key.begin(), secrets.send_key.end(),
                                       [](std::uint8_t b) { return b == 0; });
    const bool recv_zero = std::all_of(secrets.recv_key.begin(), secrets.recv_key.end(),
                                       [](std::uint8_t b) { return b == 0; });

    if (send_zero || recv_zero) {
        Logger::Error("SessionManager::ActivateSession: all-zero key rejected");
        return nullptr;
    }

    Session* session = CreateSession(std::move(secrets), peer);
    if (!session) return nullptr;

    Logger::Info("SessionManager: activated session"
                 " sender_index="   + std::to_string(session->sender_index)   +
                 " receiver_index=" + std::to_string(session->receiver_index) +
                 " peer="           + session->peer.ip.ToString() + ":" +
                                      std::to_string(session->peer.port));

    return session;
}

Session* SessionManager::TransitionSession(std::uint32_t old_sender_index,
                                           SessionSecrets new_secrets,
                                           core::network::Endpoint peer) {
    Session* new_session = ActivateSession(std::move(new_secrets), peer);

    if (!new_session) {
        Logger::Warning("SessionManager::TransitionSession: failed to create new session,"
                        " old session " + std::to_string(old_sender_index) + " remains active");
        return nullptr;
    }

    Remove(old_sender_index);
    return new_session;
}

Session* SessionManager::Lookup(std::uint32_t sender_index) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(sender_index);
    if (it == sessions_.end()) return nullptr;
    return it->second.get();
}

void SessionManager::Remove(std::uint32_t sender_index) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    sessions_.erase(sender_index);
}

Session* SessionManager::CreateSession(SessionSecrets secrets, core::network::Endpoint peer) {
    auto session = std::make_unique<Session>();

    session->send_key       = secrets.send_key;
    session->recv_key       = secrets.recv_key;
    session->sender_index   = secrets.sender_index;
    session->receiver_index = secrets.receiver_index;
    session->is_initiator   = secrets.is_initiator;
    session->created        = std::chrono::system_clock::now();
    session->peer           = peer;

    Session* raw = session.get();

    {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        sessions_[secrets.sender_index] = std::move(session);
    }

    return raw;
}

std::uint32_t SessionManager::GenerateSenderIndex() {
    for (;;) {
        std::uint32_t index = 0;
        RAND_bytes(reinterpret_cast<unsigned char*>(&index), sizeof(index));
        if (index == 0) continue;

        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (sessions_.find(index) == sessions_.end()) return index;
    }
}

std::size_t SessionManager::GetSessionCount() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return sessions_.size();
}

} // namespace core::session
