#ifndef _PQVPN_CORE_CONFIG_KEY_CONFIG_HPP_
#define _PQVPN_CORE_CONFIG_KEY_CONFIG_HPP_

#include "x25519.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace core::config {

struct KeyConfig {
    core::cryptography::x25519::PrivateKey x25519_priv;
    core::cryptography::x25519::PublicKey  x25519_pub;
    std::array<std::uint8_t, 2400>         mlkem_dk;
    std::array<std::uint8_t, 1184>         mlkem_ek;
};

// Load keys from config_path. If the file does not exist, generate a new
// keypair, save it to config_path, and return the keys.
// Returns nullopt on any error.
[[nodiscard]] auto LoadOrGenerateKeys(std::string_view config_path) -> std::optional<KeyConfig>;

// Print x25519_public and mlkem_ek to stdout for pasting into a peer config.
void PrintPublicKeys(const KeyConfig& keys);

// Write x25519_public and mlkem_ek to a file for distribution to peers.
// Returns false on I/O error.
[[nodiscard]] bool SavePublicKeys(std::string_view path, const KeyConfig& keys);

} // namespace core::config

#endif // _PQVPN_CORE_CONFIG_KEY_CONFIG_HPP_
