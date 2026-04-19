#include "secure_memory.hpp"

#include <string.h>  // explicit_bzero

namespace core::utils {

void secure_zero(void* ptr, std::size_t len) noexcept {
    // explicit_bzero() is guaranteed not to be removed by the optimiser
    // even when the buffer is never read again after this call.
    explicit_bzero(ptr, len);
}

bool ct_memcmp(
    const std::uint8_t* a,
    const std::uint8_t* b,
    std::size_t len
) noexcept {
    // XOR every byte pair into the accumulator.  The accumulator is zero iff
    // all byte pairs are equal.  The loop runs exactly len iterations so no
    // timing information leaks about where a mismatch occurs.
    unsigned int diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<unsigned int>(a[i]) ^ static_cast<unsigned int>(b[i]);
    }
    return diff == 0;
}

} // namespace core::utils
