#include "logger.hpp"
#include "client.hpp"
#include "client_config.hpp"
#include "key_config.hpp"
#include "handshake_constants.hpp"
#include "bit_utils.hpp"
#include "privileges.hpp"
#include "tunnel_setup.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>

using core::utils::Logger;
using core::utils::FromHex;
using core::network::IPv4;
using client::Client;

static bool LoadServerPublicKeys(
    std::string_view path,
    core::cryptography::x25519::PublicKey& x25519_pub,
    std::array<std::uint8_t, 1184>& mlkem_ek)
{
    std::ifstream f{std::string{path}};
    if (!f) {
        Logger::Error("main: Cannot open server public key file: " + std::string{path});
        return false;
    }

    bool got_x25519 = false;
    bool got_mlkem  = false;

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

        if (key == "x25519_public")
            got_x25519 = FromHex(val, x25519_pub);
        else if (key == "mlkem_ek")
            got_mlkem = FromHex(val, mlkem_ek);
    }

    if (!got_x25519 || !got_mlkem) {
        Logger::Error("main: server_pub.conf missing x25519_public or mlkem_ek");
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    Logger::getInstance().init(std::cerr).setLogLevel(core::utils::LogLevel::DEBUG);

    if (!core::os::HasElevatedPrivileges()) {
        Logger::Error("main: PQ_VPN_Client must be run as root");
        return 1;
    }

    auto cfg = client::ClientConfigParser{client::kClientConfigFile}.Parse();
    if (!cfg) {
        Logger::Error("main: Failed to load client config");
        return 1;
    }

    core::handshake::InitHandshakeConstants();

    auto client_keys = core::config::LoadOrGenerateKeys("client_keys.conf");
    if (!client_keys) {
        Logger::Error("main: Failed to load or generate client keys");
        return 1;
    }
    Logger::Info("main: Client keys ready");

    core::cryptography::x25519::PublicKey server_x25519_pub{};
    std::array<std::uint8_t, 1184>         server_mlkem_ek{};

    if (!LoadServerPublicKeys("server_pub.conf", server_x25519_pub, server_mlkem_ek)) {
        Logger::Error("main: Cannot start without server public keys");
        Logger::Error("main: Copy server_pub.conf from the server machine to this directory");
        return 1;
    }
    Logger::Info("main: Server public keys loaded");

    Client client;
    client.SetStaticKeys(
               client_keys->x25519_priv,
               client_keys->x25519_pub,
               client_keys->mlkem_dk,
               client_keys->mlkem_ek)
          .SetServerStaticKeys(server_x25519_pub, server_mlkem_ek)
          .SetTunInterface(cfg->tun_iface, IPv4{cfg->tun_ip});

    if (!client.Init(cfg->server_ip, cfg->server_port)) {
        Logger::Error("main: Client initialization failed");
        return 1;
    }

    if (!core::network::ConfigureClientRouting(cfg->tun_iface, cfg->firewall_mark, cfg->vpn_table)) {
        Logger::Error("main: Failed to configure tunnel routing");
        client.Shutdown();
        return 1;
    }

    std::thread worker([&client] { client.Run(); });

    Logger::Info("main: Client running — type 'q' to quit");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q") break;
    }

    client.Shutdown();
    worker.join();

    core::network::RemoveClientRouting(cfg->tun_iface, cfg->firewall_mark, cfg->vpn_table);

    Logger::Info("main: Done");
    return 0;
}
