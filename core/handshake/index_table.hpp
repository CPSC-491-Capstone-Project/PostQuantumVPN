#ifndef _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_
#define _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_

#include "handshake_state.hpp"
#include "keypair.hpp"
#include "peer.hpp"
#include "siphash.hpp"

#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace core::handshake {

struct IndexTableEntry {
    Peer*           peer{nullptr};
    HandshakeState* handshake{nullptr};
    Keypair*        keypair{nullptr};
};

struct IndexTableHasher {
    core::cryptography::siphash::Key key{};

    std::size_t operator()(std::uint32_t index) const noexcept {
        core::cryptography::siphash::SipHash24 hasher;

        std::array<std::uint8_t, sizeof(std::uint32_t)> data{};
        std::memcpy(data.data(), &index, sizeof(index));

        return static_cast<std::size_t>(hasher(key, data));
    }
};

// Thread safe map from sender_index to IndexTableEntry
// Uses SipHash internally to prevent hash flooding DoS attacks
class IndexTable {
public:
    IndexTable()
        : siphash_key_(GenerateSipHashKey())
        , table_(0, IndexTableHasher{siphash_key_}) {}

    // Generates a random uint32 index and inserts it into the table
    std::uint32_t NewIndex(Peer* peer, HandshakeState* handshake) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::uint32_t index = GenerateRandomIndex();
        while (index == 0 || table_.count(index) > 0) {
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
    static core::cryptography::siphash::Key GenerateSipHashKey() {
        core::cryptography::siphash::Key key{};
        if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
            key.fill(0);
        }
        return key;
    }

    static std::uint32_t GenerateRandomIndex() {
        std::uint32_t index = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&index),
                       static_cast<int>(sizeof(index))) != 1) {
            return 0;
        }
        return index;
    }

    using Table = std::unordered_map<std::uint32_t, IndexTableEntry, IndexTableHasher>;

    std::array<std::uint8_t, 16> siphash_key_{};
    Table table_;
    std::mutex mutex_;
};

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_INDEX_TABLE_HPP_