#include "logger.hpp"
#include "client.hpp"
#include "handshake_constants.hpp"

#include <iostream>
#include <string>
#include <thread>

using core::utils::Logger;
using client::Client;

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    Logger::getInstance().init(std::cerr).setLogLevel(core::utils::LogLevel::DEBUG);

    core::handshake::InitHandshakeConstants();

    // --- Configure and start client -------------------------------------------

    Client client;

    if (!client.Init("127.0.0.1", 51820)) {
        Logger::Error("main: Client initialization failed");
        return 1;
    }

    // Run() blocks in the event loop, so drive it on a worker thread.
    std::thread worker([&client] { client.Run(); });

    Logger::Info("main: Client running — type 'q' to quit");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "q") break;
    }

    client.Shutdown();
    worker.join();

    Logger::Info("main: Done");
    return 0;
}