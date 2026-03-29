#include "blake3.hpp"
#include "logger.hpp"

using core::utils::Logger;

namespace core::cryptography::blake3 {


    auto Hash256(std::span<const std::uint8_t> input) -> std::optional<Hash> {

        if (input.empty()) {
            Logger::Warning("Blake3: Empty data passed into Hash256");
            return std::nullopt;
        }

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input.data(), input.size());

        Hash out{};
        blake3_hasher_finalize(&hasher, out.data(), kDefaultHashBytes);

        return out;
    }

    auto KeyedHash256(
        std::span<const std::uint8_t, kDefaultHashBytes> key,
        std::span<const std::uint8_t> input
    ) -> std::optional<Hash> {

        if (input.empty()) {
            Logger::Warning("Blake3: Empty data passed into Hash256");
            return std::nullopt;
        }

        if (key.empty()) {
            Logger::Warning("Blake3: Empty key passed into KeyedHash256");
            return std::nullopt;
        }

        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, key.data());
        blake3_hasher_update(&hasher, input.data(), input.size());
 
        Hash out{};
        blake3_hasher_finalize(&hasher, out.data(), kDefaultHashBytes);
 
        return out;
    }

    auto HashXof(
        std::span<const std::uint8_t> input,
        std::size_t output_len
    ) -> std::optional<std::vector<std::uint8_t>> {

        if (input.empty()) {
            Logger::Warning("Blake3: Empty data passed into HashXof");
            return std::nullopt;
        }

        if (output_len == 0) {
            Logger::Warning("Blake3: Output length of 0 passed into HashXor");
            return std::nullopt;
        }

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, input.data(), input.size());

        std::vector<std::uint8_t> out(output_len);
        blake3_hasher_finalize(&hasher, out.data(), output_len);

        return out;
    }

} // namespace core::cryptography::blake3