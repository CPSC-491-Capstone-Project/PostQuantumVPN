#include "ipv4.hpp"
#include "logger.hpp"

#include <arpa/inet.h>

namespace core::network {

    IPv4::IPv4(const std::string& dotted) {
        // inet_pton writes a uint32_t in network byte order (big-endian)
        std::uint32_t net_order{0};

        if (::inet_pton(AF_INET, dotted.c_str(), &net_order) != 1) {
            core::utils::Logger::Warning("IPv4: Malformed address string: " + dotted);
            addr_  = 0;
            valid_ = false;
            return;
        }

        // Convert from network order to our host-order storage
        addr_ = NetworkToHost(net_order);
    }

    std::string IPv4::ToString() const {
        // inet_ntop expects network byte order
        std::uint32_t net_order = HostToNetwork(addr_);

        char buf[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &net_order, buf, sizeof(buf)) == nullptr) {
            return "0.0.0.0";
        }

        return std::string(buf);
    }

} // namespace core::network
