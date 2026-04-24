#ifndef _PQVPN_CORE_NETWORK_TUNNEL_SETUP_HPP_
#define _PQVPN_CORE_NETWORK_TUNNEL_SETUP_HPP_

#include <cstdint>
#include <string_view>

namespace core::network {

    // Routes all non-marked traffic through the tunnel interface.
    // Packets tagged with fwmark bypass the tunnel (used by the VPN socket itself).
    // Blocks IPv6 to prevent leaks.
    bool ConfigureClientRouting(std::string_view ifname, uint32_t fwmark, int routing_table);
    void RemoveClientRouting(std::string_view ifname, uint32_t fwmark, int routing_table);

    // Enables IP forwarding and installs NAT masquerade so VPN clients can
    // reach the internet through the server's outbound interface.
    // ifname is used on teardown to remove the tunnel interface.
    bool ConfigureServerNAT(std::string_view ifname, std::string_view vpn_subnet);
    void RemoveServerNAT(std::string_view ifname, std::string_view vpn_subnet);

} // namespace core::network

#endif // _PQVPN_CORE_NETWORK_TUNNEL_SETUP_HPP_
