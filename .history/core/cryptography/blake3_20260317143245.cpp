#include "blake3.hpp"

namespace core::cryptography::blake3 {

    auto Hash256(std::span<const std::uint8_t> input) -> std::optional<Hash> {

        if (input.empty()) {
            // TODO: Log Info
            return std::nullopt;
        }

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
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
            // TODO: Log Info
            return std::nullopt;
        }

        if (output_len == 0) {
            // TODO: Log Info
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