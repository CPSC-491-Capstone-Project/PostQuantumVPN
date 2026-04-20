#ifndef _PQVPN_CORE_CRYPTOGRAPHY_EVP_UTILS_HPP_
#define _PQVPN_CORE_CRYPTOGRAPHY_EVP_UTILS_HPP_

#include <memory>

#include <openssl/evp.h>

namespace core::cryptography {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};

using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY,     EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

} // namespace core::cryptography

#endif // _PQVPN_CORE_CRYPTOGRAPHY_EVP_UTILS_HPP_
