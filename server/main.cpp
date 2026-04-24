#include "logger.hpp"
#include "server.hpp"
#include "server_config.hpp"
#include "handshake_constants.hpp"
#include "key_config.hpp"

#include <iostream>
#include <string>

using core::utils::Logger;
using core::network::IPv4;
using server::Server;

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    Logger::getInstance().init(std::cerr).setLogLevel(core::utils::LogLevel::DEBUG);

    core::handshake::InitHandshakeConstants();

    auto keys = core::config::LoadOrGenerateKeys("server_keys.conf");
    if (!keys) {
        Logger::Error("main: Failed to load or generate server keys");
        return 1;
    }

    core::config::PrintPublicKeys(*keys);

    // Write public keys to server_pub.conf for distribution to clients.
    if (!core::config::SavePublicKeys("server_pub.conf", *keys)) {
        Logger::Warning("main: Failed to write server_pub.conf");
    } else {
        Logger::Info("main: Public keys written to server_pub.conf — copy to client machine");
    }

    auto cfg = server::ServerConfigParser{server::kServerConfigFile}.Parse();
    if (!cfg) {
        Logger::Error("main: Failed to load server config");
        return 1;
    }

    Server server;
    server.SetBindAddress(IPv4{cfg->bind_ip})
          .SetPort(cfg->port)
          .SetPollTimeoutMs(250)
          .SetTunInterface("pqvpn0", IPv4(10, 8, 0, 1))
          .SetStaticKeys(keys->x25519_priv, keys->x25519_pub, keys->mlkem_dk, keys->mlkem_ek);

    if (!server.Init()) {
        Logger::Error("main: Server initialization failed");
        return 1;
    }

    if (!server.Run()) {
        Logger::Error("main: Failed to start event loop");
        return 1;
    }

    Logger::Info("main: Server listening on " + cfg->bind_ip + ":" + std::to_string(cfg->port) + " — type 'q' to quit");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q") break;
    }

    server.Shutdown();
    Logger::Info("main: Done");
    return 0;
}
