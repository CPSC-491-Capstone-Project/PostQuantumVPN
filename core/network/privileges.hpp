#ifndef _PQVPN_CORE_NETWORK_PRIVILEGES_HPP_
#define _PQVPN_CORE_NETWORK_PRIVILEGES_HPP_

namespace core::os {
    // Returns true if the process has elevated (root/admin) privileges.
    bool HasElevatedPrivileges();
}

#endif // _PQVPN_CORE_NETWORK_PRIVILEGES_HPP_
