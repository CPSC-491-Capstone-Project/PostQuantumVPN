#include "tests.h"
#include "timer.hpp"

#include <string_view>
#include <iostream>
#include <iomanip>

static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

static const char* GREEN = "\033[32m";
static const char* RED = "\033[31m";
static const char* CYAN = "\033[36m";
static const char* RESET = "\033[0m";

void Run(bool (*test)(), std::string_view name) {
    total_tests++;
    core::utils::Timer timer;

    std::cout << CYAN << "[TEST] " << RESET << std::left << std::setw(40) << name;

    timer.Start();
    bool result = test();
    timer.Stop();

    if (result) {
        passed_tests++;
        std::cout << GREEN << "[PASS]" << RESET;
    } else {
        failed_tests++;
        std::cout << RED   << "[FAIL]" << RESET;
    }

    std::cout << "  " << timer.ElapsedStr() << "\n";
}

int main(int argc, char* argv[]) {

    (void)argc;
    (void)argv;

    std::cout << "========================================\n";
    std::cout << "Running Test Suite\n";
    std::cout << "========================================\n\n";

    // =============================================================================
    // Random Tests
    // =============================================================================
    
    std::cout << "\n";
    Run(RandomTest_SingletonInit, "Random: Init");
    Run(RandomTest_ZeroBytes, "Random: 0 bytes");
    Run(RandomTest_OneByte, "Random: 1 byte");
    Run(RandomTest_EightBytes, "Random: 8 bytes");
    Run(RandomTest_OneKilobyte, "Random: 1 KB");
    Run(RandomTest_3319Bytes, "Random: 3319 bytes");

    // =============================================================================
    // Bit Utils Tests
    // =============================================================================
    std::cout << "\n";
    Run(BitUtilsTest_BitsToBytes_Basic, "BitsToBytes: basic (0x01)");
    Run(BitUtilsTest_BitsToBytes_Zero, "BitsToBytes: all zeros");
    Run(BitUtilsTest_BitsToBytes_AllOnes, "BitsToBytes: all ones (0xFF)");
    Run(BitUtilsTest_BytesToBits_Basic, "BytesToBits: basic (0x01)");
    Run(BitUtilsTest_BytesToBits_Zero, "BytesToBits: all zeros");
    Run(BitUtilsTest_BytesToBits_AllOnes, "BytesToBits: all ones (0xFF)");
    Run(BitUtilsTest_Roundtrip_BytesToBits_To_BitsToBytes, "Roundtrip: BytesToBits --> BitsToBytes");
    Run(BitUtilsTest_Roundtrip_BitsToBytes_To_BytesToBits, "Roundtrip: BitsToBytes --> BytesToBits");

    // =============================================================================
    // Future Tests
    // =============================================================================

    //std::cout << std::endl;
      
    // =============================================================================
    // Test Summary
    // =============================================================================
    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    std::cout << "Total:  " << total_tests  << "\n";
    std::cout << GREEN << "Passed: " << passed_tests << RESET << "\n";
    std::cout << RED   << "Failed: " << failed_tests << RESET << "\n\n";
}

// =============================================================================
// Helper Functions
// =============================================================================
bool test_helper(std::string_view expected, std::string_view result) {
    if (result == expected) {
        return true;
    } else {
        std::cout << "\n" << RED << "  Expected: " << RESET << expected << "\n";
        std::cout         << RED << "  Got:      " << RESET << result   << "\n";
        return false;
    }
}