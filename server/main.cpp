#include "logger.hpp"
#include "server.hpp"

#include <iostream>
#include <string>


using core::utils::Logger;
using core::network::IPv4;
using server::Server;

// Uncomment for file logging
// static std::string MakeLogFilename() {
//     auto now = std::chrono::system_clock::now();
//     auto time_t_val = std::chrono::system_clock::to_time_t(now);
//     std::ostringstream oss;
//     oss << "Server_Log_"
//         << std::put_time(std::localtime(&time_t_val), "%Y%m%d_%H%M%S")
//         << ".log";
//     return oss.str();
// }

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    // --- Logger --------------------------------------------------------------
    // Console logging
    Logger::getInstance().init(std::cerr);

    // File logging — uncomment to switch:
    // Logger::getInstance().init(MakeLogFilename());

    // --- Server --------------------------------------------------------------
    Server server;
    server.SetBindAddress(IPv4::Any())
          .SetPort(51820)
          .SetPollTimeoutMs(250);

    if (!server.Init()) {
        Logger::Error("main: Server initialization failed");
        return 1;
    }

    if (!server.Run()) {
        Logger::Error("main: Server failed to start");
        return 1;
    }

    Logger::Info("main: Server running - type 'q' to quit");

    // --- Block on stdin until the user types 'q' -----------------------------
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q") {
            break;
        }
    }

    server.Shutdown();
    Logger::Info("main: Server shut down");

    return 0;
}