#ifndef _PQVPN_SERVER_KEY_CONFIG_HPP_
#define _PQVPN_SERVER_KEY_CONFIG_HPP_

#include "x25519.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace server {

struct ServerKeys {
    core::cryptography::x25519::PrivateKey x25519_priv;
    core::cryptography::x25519::PublicKey  x25519_pub;
    std::array<std::uint8_t, 2400>         mlkem_dk;
    std::array<std::uint8_t, 1184>         mlkem_ek;
};

// Load keys from config_path. If the file does not exist, generate a new
// keypair, save it to config_path, and return the generated keys.
// Returns nullopt on any error.
[[nodiscard]] auto LoadOrGenerateKeys(std::string_view config_path) -> std::optional<ServerKeys>;

// Print x25519_public and mlkem_ek to stdout in a format suitable for
// pasting into a client config file.
void PrintPublicKeys(const ServerKeys& keys);

} // namespace server

#endif // _PQVPN_SERVER_KEY_CONFIG_HPP_
