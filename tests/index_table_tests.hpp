#ifndef _PQVPN_TESTS_INDEX_TABLE_TESTS_HPP_
#define _PQVPN_TESTS_INDEX_TABLE_TESTS_HPP_

#include "test_utils.hpp"
#include "index_table.hpp"

#include <cstdint>

using core::handshake::IndexTable;
using core::handshake::IndexTableEntry;
using core::handshake::Peer;
using core::handshake::HandshakeState;
using core::handshake::Keypair;

bool IndexTableTest_NewIndex_InsertAndLookup() {
    IndexTable table;

    auto* peer      = reinterpret_cast<Peer*>(0x1000);
    auto* handshake = reinterpret_cast<HandshakeState*>(0x2000);

    std::uint32_t index = table.NewIndex(peer, handshake);
    if (index == 0) {
        return false;
    }

    auto entry = table.Lookup(index);
    if (!entry.has_value()) {
        return false;
    }

    return entry->peer == peer &&
           entry->handshake == handshake &&
           entry->keypair == nullptr;
}

bool IndexTableTest_Lookup_MissingIndex() {
    IndexTable table;

    auto entry = table.Lookup(0xDEADBEEF);
    return !entry.has_value();
}

bool IndexTableTest_NewIndex_UniqueIndices() {
    IndexTable table;

    auto* peer1      = reinterpret_cast<Peer*>(0x1000);
    auto* handshake1 = reinterpret_cast<HandshakeState*>(0x2000);

    auto* peer2      = reinterpret_cast<Peer*>(0x3000);
    auto* handshake2 = reinterpret_cast<HandshakeState*>(0x4000);

    std::uint32_t index1 = table.NewIndex(peer1, handshake1);
    std::uint32_t index2 = table.NewIndex(peer2, handshake2);

    return index1 != 0 &&
           index2 != 0 &&
           index1 != index2;
}

bool IndexTableTest_SwapHandshakeToKeypair_UpdatesEntry() {
    IndexTable table;

    auto* peer      = reinterpret_cast<Peer*>(0x1000);
    auto* handshake = reinterpret_cast<HandshakeState*>(0x2000);
    auto* keypair   = reinterpret_cast<Keypair*>(0x3000);

    std::uint32_t index = table.NewIndex(peer, handshake);
    if (index == 0) {
        return false;
    }

    table.SwapHandshakeToKeypair(index, keypair);

    auto entry = table.Lookup(index);
    if (!entry.has_value()) {
        return false;
    }

    return entry->peer == peer &&
           entry->handshake == nullptr &&
           entry->keypair == keypair;
}

bool IndexTableTest_Delete_RemovesEntry() {
    IndexTable table;

    auto* peer      = reinterpret_cast<Peer*>(0x1000);
    auto* handshake = reinterpret_cast<HandshakeState*>(0x2000);

    std::uint32_t index = table.NewIndex(peer, handshake);
    if (index == 0) {
        return false;
    }

    table.Delete(index);

    auto entry = table.Lookup(index);
    return !entry.has_value();
}

#endif // _PQVPN_TESTS_INDEX_TABLE_TESTS_HPP_