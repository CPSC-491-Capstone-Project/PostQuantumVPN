#ifndef _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_
#define _PQVPN_CORE_HANDSHAKE_HELPERS_HPP_

#include "handshake_constants.hpp"
#include "blake3.hpp"
#include "bit_utils.hpp"

namespace core::handshake {

// ---------------------------------------------------------------------------
// MixHash
// ---------------------------------------------------------------------------
 
inline void MixHash(
    std::array<std::uint8_t, BLAKE3_OUT_LEN>& hash,
    ConstByteSpan data) 
{
    

}


} // namespace core::handshake


#endif //_PQVPN_CORE_HANDSHAKE_HELPERS_HPP_