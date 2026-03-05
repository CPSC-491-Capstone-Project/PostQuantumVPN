#ifndef _PQVPN_CORE_CRYPTOGRAPHY_SIPHASH_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_SIPHASH_HPP_

#include <cstdint>
#include <array>
#include <span>
#include <cstring>
#include <string_view>

namespace core::cryptography::siphash {

    inline constexpr uint64_t kMagicNumber0 = 0x736f6d6570736575;
    inline constexpr uint64_t kMagicNumber1 = 0x646f72616e646f6d;
    inline constexpr uint64_t kMagicNumber2 = 0x6c7967656e657261;
    inline constexpr uint64_t kMagicNumber3 = 0x7465646279746573;

    inline constexpr std::size_t kKeyBytes = 16;
    inline constexpr std::size_t kHashBytes = 8;

    using Key = std::array<std::uint8_t, kKeyBytes>;
    using Data = std::span<const std::uint8_t>;
    using Result = uint64_t;


    // C - Compression Rounds
    // D - Finalization Rounds
    // <2, 4> is standard
    template <int CRounds, int DRounds>
    class SipHash {
        static_assert(CRounds >= 1 && DRounds >= 1, "SipHash must have at least 1 Compression Round and 1 Finalization Round.");

    public:
    
        [[nodiscard]] Result operator()(const Key& key, Data data) const noexcept;

    private:
        struct State {
            std::uint64_t v0;
            std::uint64_t v1;
            std::uint64_t v2;
            std::uint64_t v3;
        };

        static void SipRound(State& s) noexcept;
    };

    using SipHash24 = SipHash<2, 4>;


    // Normalization functions to handle strings 
    // and other byte containers

    [[nodiscard]] inline Key NormalizeKey(Data input) noexcept {
        Key key{};
        const auto len = std::min(input.size(), kKeyBytes);
        std::memcpy(key.data(), input.data(), len);
        return key;
    }

    [[nodiscard]] inline Key NormalizeKey(std::string_view input) noexcept {
        return NormalizeKey(Data{
            reinterpret_cast<const uint8_t*>(input.data()),
            input.size()
        });
    }

    [[nodiscard]] inline Data NormalizeData(Data input) noexcept {
        return input;
    }

    [[nodiscard]] inline Data NormalizeData(std::string_view input) noexcept {
        return {
            reinterpret_cast<const uint8_t*>(input.data()),
            input.size()
        };
    }

} // namespace core::cryptography::siphash

#endif // _PQVPN_CORE_CRYPTOGRAPHY_SIPHASH_HPP_