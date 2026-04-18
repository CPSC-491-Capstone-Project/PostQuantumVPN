#ifndef _PQVPN_CORE_HANDSHAKE_PROCESSOR_HPP_
#define _PQVPN_CORE_HANDSHAKE_PROCESSOR_HPP_

#include "handshake_constants.hpp"
#include "peer.hpp"
#include "index_table.hpp"

#include <optional>
#include <vector>

namespace core::handshake {

// Creates a Type 1 (initiation) message. Modifies peer.handshake and registers
// a sender index in the index table. MAC fields are left zeroed — fill them
// via the MAC system (DG-244) before sending.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
CreateMessageInitiation(Peer& peer, IndexTable& index_table);

// Processes a received Type 1 message. On success, commits state to
// peer.handshake and returns true. Drops silently on any failure.
[[nodiscard]] bool
ConsumeMessageInitiation(ConstByteSpan msg, Peer& peer);

// Creates a Type 2 (response) message. Requires peer.handshake to be in
// InitiationConsumed state. MAC fields are left zeroed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
CreateMessageResponse(Peer& peer, IndexTable& index_table);

// Processes a received Type 2 message. On success, sets peer.handshake to
// ResponseConsumed and returns true.
[[nodiscard]] bool
ConsumeMessageResponse(ConstByteSpan msg, Peer& peer, IndexTable& index_table);

// Derives transport session keys from the completed handshake chaining key.
// Installs a new Keypair into peer.keypairs, registers it in the index table,
// and zeroes the chaining key and hash from handshake state.
[[nodiscard]] bool
DeriveSessionKeys(Peer& peer, IndexTable& index_table, bool is_initiator);

} // namespace core::handshake

#endif // _PQVPN_CORE_HANDSHAKE_PROCESSOR_HPP_
