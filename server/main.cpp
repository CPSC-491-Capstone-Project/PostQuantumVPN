#include "logger.hpp"

#include <iostream>

using core::utils::Logger;

int main(int argc, char* argv[]) {

    (void)argc;
    (void)argv;

    // Initialize the global logger as everything will need this
    Logger::getInstance().init(std::cerr);


    std::cout << "Hello World!" << std::endl;

    return 0;
}