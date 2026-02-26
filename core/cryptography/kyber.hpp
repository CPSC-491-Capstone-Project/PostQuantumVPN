#ifndef _PQVPN_CORE_CRYPTOGRAPHY_KYBER_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_KYBER_HPP_

#include <cstdint>
#include <span>


namespace core::cryptography::kyber {

    constexpr uint16_t Q = 3329;
    constexpr std::size_t N = 256;

    // === Encoding/Compression (Section 4.2.1) ===

    // Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
    void ByteEncode(uint8_t d, std::span<const uint16_t, N> F, std::span<uint8_t> bytes);

    // Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
    void ByteDecode(uint8_t d, std::span<const uint8_t> bytes, std::span<int16_t, N> F);


} // namespace core::cryptography::kyber


#endif // _PQVPN_CORE_CRYPTOGRAPHY_KYBER_HPP_