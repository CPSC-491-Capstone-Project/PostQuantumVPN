#ifndef _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_
#define _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_

#include "handshake_state.hpp"
#include "siphash.hpp"
#include "chacha20_poly1305.hpp"
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace core::handshake {

// Forward declarations - defined by peer and session modules
struct Peer;
struct Keypair;

struct IndexTableEntry {
    Peer*           peer{nullptr};
    HandshakeState* handshake{nullptr};
    Keypair*        keypair{nullptr};
};

// Thread safe map from sender_index to IndexTableEntry
// Uses SipHash internally to prevent hash flooding DoS attacks
class IndexTable {
public:

    IndexTable() {
        auto key = core::cryptography::chacha20_poly1305::GenerateKey();
        if (key) {
            std::copy(key->begin(), key->begin() + 16, siphash_key_.begin());
        }
    }

    // Generates a random uint32 index and inserts it into the table
    std::uint32_t NewIndex(Peer* peer, HandshakeState* handshake) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::uint32_t index = GenerateRandomIndex();
        while (table_.count(index) > 0) {
            index = GenerateRandomIndex();
        }

        table_[index] = IndexTableEntry{peer, handshake, nullptr};
        return index;
    }

    std::optional<IndexTableEntry> Lookup(std::uint32_t index) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = table_.find(index);
        if (it == table_.end()) {
            return std::nullopt;
        }

        return it->second;
    }

    // Replaces handshake pointer with keypair pointer when handshake completes
    void SwapHandshakeToKeypair(std::uint32_t index, Keypair* keypair) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = table_.find(index);
        if (it != table_.end()) {
            it->second.handshake = nullptr;
            it->second.keypair   = keypair;
        }
    }

    void Delete(std::uint32_t index) {
        std::lock_guard<std::mutex> lock(mutex_);
        table_.erase(index);
    }

private:

    std::uint32_t GenerateRandomIndex() {
        auto key = core::cryptography::chacha20_poly1305::GenerateKey();
        if (!key) return 0;

        std::uint32_t index = 0;
        std::memcpy(&index, key->data(), sizeof(std::uint32_t));
        return index;
    }

    std::unordered_map<std::uint32_t, IndexTableEntry> table_;
    std::array<std::uint8_t, 16> siphash_key_{};
    std::mutex mutex_;
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_