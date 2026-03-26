#include "bit_utils.hpp"


namespace core::utils {

    void BitsToBytes(ConstByteSpan bits, ByteSpan bytes) {
        const auto num_bytes = bits.size() / 8uz;

        for (auto i{0uz}; i < num_bytes; ++i) {
            const auto base = i * 8uz;
            Byte byte{};
            for (auto j{0uz}; j < 8uz; ++j) {
                byte |= static_cast<Byte>((bits[base + j] & 1u) << j);
            }
            bytes[i] = byte;
        }
    }

    void BytesToBits(ConstByteSpan bytes, ByteSpan bits) {
        for (auto i{0uz}; i < bytes.size(); ++i) {
            auto c = bytes[i];
            for (auto j{0uz}; j < 8uz; ++j) {
                bits[8uz * i + j] = c & 1u;
                c >>= 1;
            }
        }
    }


} // namespace core::utils