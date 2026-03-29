#include "handshake_helpers.hpp"

using core::cryptography::blake3::Hash256;

namespace core::handshake {

void MixHash(Blake3Hash& hash, ConstByteSpan data) {
    // H = HASH(H || data)
    std::vector<std::uint8_t> buf;
    buf.reserve(hash.size() + data.size());
    buf.insert(buf.end(), hash.begin(), hash.end());
    buf.insert(buf.end(), data.begin(), data.end());

    auto result = Hash256(ConstByteSpan{buf.data(), buf.size()});

    if (!result) {
        // H is always 32 bytes, so buf is never empty.
        // Hash256 only fails on empty input - this path is unreachable
        // under normal operation, but zero the hash defensively.
        hash.fill(0);
        return;
    }

    hash = *result;
}

} // namespace core::handshake