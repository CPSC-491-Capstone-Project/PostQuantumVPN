#ifndef _PQVPN_CORE_UTILS_SECURE_MEMORY_HPP_
#define _PQVPN_CORE_UTILS_SECURE_MEMORY_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace core::utils {

// ---------------------------------------------------------------------------
// secure_zero
// ---------------------------------------------------------------------------
// Zeroes len bytes at ptr in a way the compiler cannot eliminate.
// Delegates to explicit_bzero(), which is guaranteed not to be removed
// by the optimiser even when the buffer is never read again.
//
// Call this on every secret — private keys, shared secrets, KDF outputs —
// immediately after the value is no longer needed.
// ---------------------------------------------------------------------------
void secure_zero(void* ptr, std::size_t len) noexcept;

// Convenience overload for fixed-size byte arrays (e.g. Blake3Hash, Key).
template <std::size_t N>
void secure_zero(std::array<std::uint8_t, N>& arr) noexcept {
    secure_zero(arr.data(), N);
}

// ---------------------------------------------------------------------------
// ct_memcmp
// ---------------------------------------------------------------------------
// Compares len bytes of a and b in constant time: the XOR of every byte pair
// is folded into an accumulator, so the loop always runs len iterations
// regardless of where (or whether) a mismatch occurs.  No timing information
// leaks about the position of the first differing byte.
//
// Returns true if the two regions are equal, false otherwise.
//
// Never substitute memcmp() for MAC, authentication-tag, or key comparisons —
// memcmp() short-circuits on the first differing byte, leaking information.
// ---------------------------------------------------------------------------
[[nodiscard]] bool ct_memcmp(
    const std::uint8_t* a,
    const std::uint8_t* b,
    std::size_t len
) noexcept;

// Span overload — also verifies that the two spans have the same length.
[[nodiscard]] inline bool ct_memcmp(
    std::span<const std::uint8_t> a,
    std::span<const std::uint8_t> b
) noexcept {
    if (a.size() != b.size()) return false;
    return ct_memcmp(a.data(), b.data(), a.size());
}

// Fixed-size array overload.
template <std::size_t N>
[[nodiscard]] bool ct_memcmp(
    const std::array<std::uint8_t, N>& a,
    const std::array<std::uint8_t, N>& b
) noexcept {
    return ct_memcmp(a.data(), b.data(), N);
}

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_SECURE_MEMORY_HPP_
