#ifndef _PQVPN_SERVER_KEY_CONFIG_HPP_
#define _PQVPN_SERVER_KEY_CONFIG_HPP_
// Moved to core/config/key_config.hpp
#include "config/key_config.hpp"
namespace server {
    using KeyConfig = core::config::KeyConfig;
    using core::config::LoadOrGenerateKeys;
    using core::config::PrintPublicKeys;
}
#endif // _PQVPN_SERVER_KEY_CONFIG_HPP_
