#ifndef _PQVPN_CORE_UTILS_BIT_UTILS_HPP_
#define _PQVPN_CORE_UTILS_BIT_UTILS_HPP_

#include <cstdint>
#include <vector>

namespace core::utils {

    std::vector<uint8_t> BitsToBytes(const std::vector<uint8_t>& bits);
    std::vector<uint8_t> BytesToBits(const std::vector<uint8_t>& bytes);

} // namespace core::utils

#endif // _PQVPN_CORE_UTILS_BIT_UTILS_HPP_