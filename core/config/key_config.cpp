#include "key_config.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"
#include "logger.hpp"
#include "bit_utils.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

namespace core::config {

using core::utils::Logger;
using core::utils::ToHex;
using core::utils::FromHex;

static bool SaveKeys(std::string_view path, const KeyConfig& keys) {
    std::ofstream f{std::string{path}};
    if (!f) return false;

    f << "# PostQuantumVPN Keys\n"
      << "# Keep this file private — it contains secret keys.\n"
      << "# Share x25519_public and mlkem_ek with peers.\n\n"
      << "x25519_private = " << ToHex(keys.x25519_priv) << "\n"
      << "x25519_public = "  << ToHex(keys.x25519_pub)  << "\n"
      << "mlkem_dk = "       << ToHex(keys.mlkem_dk)    << "\n"
      << "mlkem_ek = "       << ToHex(keys.mlkem_ek)    << "\n";

    return f.good();
}

static bool LoadKeys(std::string_view path, KeyConfig& out) {
    std::ifstream f{std::string{path}};
    if (!f) return false;

    bool got[4]{};

    std::string line;
    while (std::getline(f, line)) {
        auto s = line.find_first_not_of(" \t\r");
        if (s == std::string::npos || line[s] == '#') continue;
        line = line.substr(s);

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        if (auto e = key.find_last_not_of(" \t"); e != std::string::npos)
            key = key.substr(0, e + 1);

        std::string val = line.substr(eq + 1);
        if (auto vs = val.find_first_not_of(" \t"); vs != std::string::npos)
            val = val.substr(vs);
        if (auto ve = val.find_last_not_of(" \t\r\n"); ve != std::string::npos)
            val = val.substr(0, ve + 1);

        if      (key == "x25519_private") got[0] = FromHex(val, out.x25519_priv);
        else if (key == "x25519_public")  got[1] = FromHex(val, out.x25519_pub);
        else if (key == "mlkem_dk")       got[2] = FromHex(val, out.mlkem_dk);
        else if (key == "mlkem_ek")       got[3] = FromHex(val, out.mlkem_ek);
    }

    return got[0] && got[1] && got[2] && got[3];
}

auto LoadOrGenerateKeys(std::string_view config_path) -> std::optional<KeyConfig> {
    KeyConfig keys{};

    if (std::ifstream probe{std::string{config_path}}; probe.good()) {
        probe.close();
        if (!LoadKeys(config_path, keys)) {
            Logger::Error("key_config: Failed to parse " + std::string(config_path));
            return std::nullopt;
        }
        Logger::Info("key_config: Loaded keys from " + std::string(config_path));
        return keys;
    }

    auto x25519_kp = core::cryptography::x25519::GenerateKeyPair();
    if (!x25519_kp) {
        Logger::Error("key_config: Failed to generate X25519 keypair");
        return std::nullopt;
    }

    auto mlkem_kp = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!mlkem_kp) {
        Logger::Error("key_config: Failed to generate ML-KEM keypair");
        return std::nullopt;
    }

    std::size_t dk_len = 0;
    if (EVP_PKEY_get_octet_string_param(mlkem_kp->pkey.get(),
            OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0, &dk_len) <= 0
        || dk_len != 2400) {
        Logger::Error("key_config: Failed to query ML-KEM dk size (got "
                      + std::to_string(dk_len) + ", expected 2400)");
        return std::nullopt;
    }
    if (EVP_PKEY_get_octet_string_param(mlkem_kp->pkey.get(),
            OSSL_PKEY_PARAM_PRIV_KEY, keys.mlkem_dk.data(), keys.mlkem_dk.size(), &dk_len) <= 0) {
        Logger::Error("key_config: Failed to extract ML-KEM dk");
        return std::nullopt;
    }

    keys.x25519_priv = x25519_kp->private_key;
    keys.x25519_pub  = x25519_kp->public_key;
    std::copy(mlkem_kp->public_key.begin(), mlkem_kp->public_key.end(), keys.mlkem_ek.begin());

    if (!SaveKeys(config_path, keys)) {
        Logger::Error("key_config: Failed to save keys to " + std::string(config_path));
        return std::nullopt;
    }

    Logger::Info("key_config: Generated new keys -> " + std::string(config_path));
    return keys;
}

void PrintPublicKeys(const KeyConfig& keys) {
    std::cout << "\n=== Public Keys (share these with peers) ===\n"
              << "x25519_public = " << ToHex(keys.x25519_pub) << "\n"
              << "mlkem_ek = "      << ToHex(keys.mlkem_ek)   << "\n"
              << "============================================\n\n";
}

bool SavePublicKeys(std::string_view path, const KeyConfig& keys) {
    std::ofstream f{std::string{path}};
    if (!f) return false;
    f << "# PostQuantumVPN Server Public Keys\n"
      << "# Copy this file to the client machine.\n\n"
      << "x25519_public = " << ToHex(keys.x25519_pub) << "\n"
      << "mlkem_ek = "      << ToHex(keys.mlkem_ek)   << "\n";
    return f.good();
}

} // namespace core::config
