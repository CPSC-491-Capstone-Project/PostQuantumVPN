#ifndef _PQVPN_CORE_UTILS_RANDOM_HPP_
#define _PQVPN_CORE_UTILS_RANDOM_HPP_

#include <chrono>
#include <random>
#include <cstdint>
#include <vector>
#include <cstring>
#include <stdexcept>

namespace core::utils {

    // Singleton class for generating random bytes
    class Random{
    public:
        Random() = delete;
        
        static std::vector<uint8_t> GenerateNRandomBytes(std::size_t n) {
            std::vector<uint8_t> buffer(n);
            FillBytes(buffer.data(), n);
            return buffer;
        }

    private:
        static std::mt19937_64& Engine() {
            static std::mt19937_64 engine = []() {
                std::random_device rd{};
                std::seed_seq ss{
                    static_cast<std::seed_seq::result_type>(
                        std::chrono::steady_clock::now().time_since_epoch().count()),
                    rd(), rd(), rd(), rd(), rd(), rd(), rd()
                };
                return std::mt19937_64{ss};
            }();
            return engine;
        }

        static void FillBytes(uint8_t* __restrict__ dst, std::size_t n) {
            auto& eng = Engine();

            const std::size_t chunks = n / sizeof(uint64_t);
            const std::size_t remainder = n % sizeof(uint64_t);

            auto* dst64 = reinterpret_cast<uint64_t*>(dst);
            for (std::size_t i{0uz}; i < chunks; ++i) {
                dst64[i] = eng();
            }

            if (remainder > 0) {
                uint64_t last = eng();
                std::memcpy(dst + chunks * sizeof(uint64_t), &last, remainder);
            }
        }
    };

} // namespace core::utils


#endif // _PQVPN_CORE_UTILS_RANDOM_HPP_