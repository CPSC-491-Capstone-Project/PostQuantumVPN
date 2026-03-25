#ifndef _PQVPN_CORE_UTILS_TAI64N_HPP_
#define _PQVPN_CORE_UTILS_TAI64N_HPP_

#include "bit_utils.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace core::utils {

class Tai64nStamp {
public:
    static constexpr std::size_t kSize = 12;
    
    Tai64nStamp() = delete;
    Tai64nStamp(std::uint64_t seconds, std::uint32_t nanoseconds);
    
    [[nodiscard]] constexpr bool operator==(const Tai64nStamp&) const = default;
    [[nodiscard]] constexpr auto operator<=>(const Tai64nStamp&) const = default;

    constexpr Tai64nStamp& operator++();

    [[nodiscard]] std::uint64_t Hash() const;

    [[nodiscard]] constexpr std::uint64_t Seconds() const;
    [[nodiscard]] constexpr std::uint32_t Nanoseconds() const;

private:
    std::array<uint8_t, kSize> data_;
};

class Tai64n {
public:
    static constexpr std::uint64_t kTai64Label = 0x4000000000000000ULL;

    using seconds = std::chrono::seconds;
    using nano_seconds = std::chrono::nanoseconds;

    [[nodiscard]] Tai64nStamp Now();

private:
    std::mutex mutex_;
    Tai64nStamp last_;

};

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_TAI64N_HPP_