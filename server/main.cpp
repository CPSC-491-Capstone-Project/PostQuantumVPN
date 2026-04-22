#include "logger.hpp"
#include "server.hpp"

#include <iostream>
#include <string>

using core::utils::Logger;
using core::network::IPv4;
using server::Server;

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    Logger::getInstance().init(std::cerr).setLogLevel(core::utils::LogLevel::DEBUG);

    Server server;
    server.SetBindAddress(IPv4::Any())
          .SetPort(51820)
          .SetPollTimeoutMs(250)
          .SetTunInterface("pqvpn0", IPv4(10, 8, 0, 1));

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
