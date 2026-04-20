#include "siphash.hpp"
#include "bit_utils.hpp"

#include <bit>


namespace core::cryptography::siphash {

    using core::utils::load64_le;

    template <int CRounds, int DRounds>
    void SipHash<CRounds, DRounds>::SipRound(State& s) noexcept {
        s.v0 += s.v1;
        s.v2 += s.v3;
        s.v1 = std::rotl(s.v1, 13);
        s.v3 = std::rotl(s.v3, 16);
        s.v1 ^= s.v0;
        s.v3 ^= s.v2;
        s.v0 = std::rotl(s.v0, 32);
        s.v2 += s.v1;
        s.v0 += s.v3;
        s.v1 = std::rotl(s.v1, 17);
        s.v3 = std::rotl(s.v3, 21);
        s.v1 ^= s.v2;
        s.v3 ^= s.v0;

        s.v2 = std::rotl(s.v2, 32);
    }

    template <int CRounds, int DRounds>
    Result SipHash<CRounds, DRounds>::operator()(const Key& key, ConstData data) const noexcept {

        const uint64_t k0 = load64_le(key.data());
        const uint64_t k1 = load64_le(key.data() + 8);

        State s {
            .v0 = kMagicNumber0 ^ k0,
            .v1 = kMagicNumber1 ^ k1,
            .v2 = kMagicNumber2 ^ k0,
            .v3 = kMagicNumber3 ^ k1
        };

        const std::size_t msgLen = data.size();
        const std::size_t fullBlocks = msgLen / 8;

        for (std::size_t i{}; i < fullBlocks; ++i) {
            const uint64_t mi = load64_le(data.data() + (i * 8));
            s.v3 ^= mi;
            for (int i{}; i < CRounds; ++i) {
                SipRound(s);
            }
            s.v0 ^= mi;
        }

        // Final block: remaining bytes + length encoding
        // The last word contains the remaining 0-7 bytes, padded with 0x00
        // with (msgLen % 256) in the high byte

        uint64_t last{static_cast<uint64_t>(msgLen & 0xFF) << 56};

        const std::size_t remaining = msgLen % 8;
        const uint8_t* tail = data.data() + (fullBlocks * 8);

        for (std::size_t i{}; i < remaining; ++i) {
            last |= static_cast<uint64_t>(tail[i]) << (i * 8);
        }

        s.v3 ^= last;
        for (int i{}; i < CRounds; ++i) {
            SipRound(s);
        }
        s.v0 ^= last;

        s.v2 ^= 0xFF;
        for (int i{}; i < DRounds; ++i) {
            SipRound(s);
        }

        return s.v0 ^ s.v1 ^ s.v2 ^ s.v3;
    }

    template class SipHash<2, 4>;

} // namespace core::cryptography::siphash