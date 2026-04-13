#include "logger.hpp"
#include "server.hpp"

#include <iostream>

using core::utils::Logger;
using server::Server;

int main(int argc, char* argv[]) {

    (void)argc;
    (void)argv;

    // Initialize the global logger as everything will need this
    Logger::getInstance().init(std::cerr);

    Server server{};


    std::cout << "Hello World!" << std::endl;

    return 0;
}