#include "handshake_constants.hpp"
#include "logger.cpp"

#include <atomic>
#include <vector>

using core::utils::Logger;
using core::cryptography::blake3::Hash256;

namespace core::handshake {

static Blake3Hash g_initial_chaining_key{};
static Blake3Hash g_initial_hash{};
static std::atomic<bool> g_initialized{false};

const Blake3Hash& InitialChainingKey() {
    return g_initial_chaining_key;
}

const Blake3Hash& InitialHash() {
    return g_initial_hash;
}

void InitHandshakeConstants() {
    if (g_initialized.load(std::memory_order_acquire)) {
        return;
    }

    // C = HASH(kConstruction)
    auto result = Hash256(ConstByteSpan{
        reinterpret_cast<const std::uint8_t*>(kConstruction.data()),
        kConstruction.size()
    });

    if (!result) {
        Logger::Emergency("InitHandshakeConstants: Failed to hash construction string");
        return;
    }

    g_initial_chaining_key = *result;

    // H = HASH(C || kIdentifier)
    {
        std::vector<std::uint8_t> buf;
        buf.reserve(g_initial_chaining_key.size() + kIdentifier.size());
        buf.insert(buf.end(), g_initial_chaining_key.begin(), g_initial_chaining_key.end());
        buf.insert(buf.end(),
            reinterpret_cast<const std::uint8_t*>(kIdentifier.data()),
            reinterpret_cast<const std::uint8_t*>(kIdentifier.data()) + kIdentifier.size()
        );

        auto result = Hash256(ConstByteSpan{buf.data(), buf.size()});

        if (!result) {
            Logger::Emergency("InitHandshakeConstants: Failed to hash C || identifier");
            return;
        }

        g_initial_hash = *result;
    }

    g_initialized.store(true, std::memory_order_release);
    Logger::Info("InitHandshakeConstants: Protocol constants initialized");
}


} // namespace core::handshake