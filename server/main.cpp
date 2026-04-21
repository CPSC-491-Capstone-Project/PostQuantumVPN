#include "logger.hpp"
#include "server.hpp"
#include "handshake_constants.hpp"
#include "x25519.hpp"
#include "ml_kem.hpp"

#include <iostream>
#include <string>

#include <openssl/evp.h>

using core::utils::Logger;
using core::network::IPv4;
using server::Server;

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    Logger::getInstance().init(std::cerr).setLogLevel(core::utils::LogLevel::DEBUG);

    core::handshake::InitHandshakeConstants();

    // --- Generate server static keys -------------------------------------------

    auto x25519_kp = core::cryptography::x25519::GenerateKeyPair();
    if (!x25519_kp) {
        Logger::Error("main: Failed to generate X25519 keypair");
        return 1;
    }

    auto mlkem_kp = core::cryptography::ml_kem::GenerateKeyPair(
        core::cryptography::ml_kem::ParameterSet::ML_KEM_768);
    if (!mlkem_kp) {
        Logger::Error("main: Failed to generate ML-KEM keypair");
        return 1;
    }

    // Extract ML-KEM decapsulation key (private key bytes)
    std::array<std::uint8_t, 2400> mlkem_dk{};
    std::size_t dk_len = 2400;
    if (EVP_PKEY_get_raw_private_key(mlkem_kp->pkey.get(), mlkem_dk.data(), &dk_len) != 1
        || dk_len != 2400) {
        Logger::Error("main: Failed to extract ML-KEM decapsulation key");
        return 1;
    }

    std::array<std::uint8_t, 1184> mlkem_ek{};
    std::copy(mlkem_kp->public_key.begin(), mlkem_kp->public_key.end(), mlkem_ek.begin());

    Logger::Info("main: Server static keys generated");

    // --- Configure and start server --------------------------------------------

    Server server;
    server.SetBindAddress(IPv4::Any())
          .SetPort(51820)
          .SetPollTimeoutMs(250)
          .SetTunInterface("pqvpn0", IPv4(10, 8, 0, 1))
          .SetStaticKeys(x25519_kp->private_key, x25519_kp->public_key, mlkem_dk, mlkem_ek);

    if (!server.Init()) {
        Logger::Error("main: Server initialization failed");
        return 1;
    }

    if (!server.Run()) {
        Logger::Error("main: Failed to start event loop");
        return 1;
    }

    Logger::Info("main: Server listening on 0.0.0.0:51820 — type 'q' to quit");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q") break;
    }

    server.Shutdown();
    Logger::Info("main: Done");
    return 0;
}
