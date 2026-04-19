#include "tun_device.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <linux/if_tun.h>

using core::utils::Logger;

namespace core::network {

    TunDevice::~TunDevice() {
        Close();
    }

    TunDevice::TunDevice(TunDevice&& other) noexcept
        : handle_{std::exchange(other.handle_, kInvalidHandle)}
        , ifname_{std::exchange(other.ifname_, {})}
    {}

    TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = std::exchange(other.handle_, kInvalidHandle);
            ifname_ = std::exchange(other.ifname_, {});
        }
        return *this;
    }

    bool TunDevice::Open(std::string_view ifname) {
        if (IsOpen()) {
            Logger::Warning("TunDevice: Open called on already open device");
            return false;
        }

        int fd = ::open("/dev/net/tun", O_RDWR);
        if (fd < 0) {
            Logger::Emergency("TunDevice: Failed to open /dev/net/tun");
            return false;
        }

        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, ifname.data(), IFNAMSIZ - 1);

        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            Logger::Emergency("TunDevice: ioctl TUNSETIFF failed for interface: " + std::string(ifname));
            ::close(fd);
            return false;
        }

        handle_ = static_cast<Handle>(fd);
        ifname_ = std::string(ifname);
        return true;
    }

    void TunDevice::Close() {
        if (IsOpen()) {
            ::close(handle_);
            handle_ = kInvalidHandle;
            ifname_.clear();
        }
    }

    bool TunDevice::SetNonBlocking(bool non_blocking) {
        if (!IsOpen()) {
            Logger::Error("TunDevice: SetNonBlocking called on closed device");
            return false;
        }

        std::int32_t flags = ::fcntl(handle_, F_GETFL, 0);
        if (flags < 0) {
            Logger::Error("TunDevice: Failed to get flags for handle: " + std::to_string(handle_));
            return false;
        }

        flags = non_blocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);

        if (::fcntl(handle_, F_SETFL, flags) < 0) {
            Logger::Error("TunDevice: Failed to set non-blocking for handle: " + std::to_string(handle_));
            return false;
        }

        return true;
    }

    BytesTransferred TunDevice::Read(Data buf) {
        if (!IsOpen()) {
            Logger::Error("TunDevice: Read called on closed device");
            return -1;
        }

        BytesTransferred len = ::read(handle_, buf.data(), buf.size());
        if (len < 0) {
            Logger::Error("TunDevice: Read failed for handle: " + std::to_string(handle_));
        }

        return len;
    }

    BytesTransferred TunDevice::Write(ConstData buf) {
        if (!IsOpen()) {
            Logger::Error("TunDevice: Write called on closed device");
            return -1;
        }

        BytesTransferred len = ::write(handle_, buf.data(), buf.size());
        if (len < 0) {
            Logger::Error("TunDevice: Write failed for handle: " + std::to_string(handle_));
        }

        return len;
    }

    bool TunDevice::BringUp(IPv4 ip) {
        if (!IsOpen()) {
            Logger::Error("TunDevice: BringUp called on closed device");
            return false;
        }

        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            Logger::Error("TunDevice: BringUp failed to open control socket");
            return false;
        }

        // Set IP address
        struct ifreq ifr{};
        strncpy(ifr.ifr_name, ifname_.c_str(), IFNAMSIZ - 1);
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        addr->sin_family = AF_INET;
        std::uint32_t ip_net = ip.ToNetworkOrder();
        memcpy(&addr->sin_addr, &ip_net, 4);
        if (::ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
            Logger::Error("TunDevice: SIOCSIFADDR failed for " + ifname_);
            ::close(fd);
            return false;
        }

        // Set /24 netmask — causes the kernel to install a connected subnet route
        // when the interface is brought UP below.
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname_.c_str(), IFNAMSIZ - 1);
        auto* mask = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
        mask->sin_family = AF_INET;
        std::uint32_t mask_net = IPv4(255, 255, 255, 0).ToNetworkOrder();
        memcpy(&mask->sin_addr, &mask_net, 4);
        ::ioctl(fd, SIOCSIFNETMASK, &ifr);

        // Bring UP + RUNNING — subnet route is created here
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname_.c_str(), IFNAMSIZ - 1);
        ::ioctl(fd, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        bool ok = (::ioctl(fd, SIOCSIFFLAGS, &ifr) == 0);
        if (!ok) Logger::Error("TunDevice: SIOCSIFFLAGS failed for " + ifname_);

        ::close(fd);
        return ok;
    }

    bool TunDevice::Exists(std::string_view name) {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return false;
        struct ifreq ifr{};
        strncpy(ifr.ifr_name, name.data(), IFNAMSIZ - 1);
        bool exists = (::ioctl(fd, SIOCGIFFLAGS, &ifr) == 0);
        ::close(fd);
        return exists;
    }

    bool TunDevice::HasRequiredPrivileges() {
        return ::geteuid() == 0;
    }

    // ---------------------------------------------------------------------------
    // Pure packet helpers — no OS headers required beyond what is already included
    // ---------------------------------------------------------------------------

    uint16_t TunDevice::IpChecksum(ConstData header) noexcept {
        const auto* p = reinterpret_cast<const uint16_t*>(header.data());
        uint32_t sum = 0;
        std::size_t len = header.size();
        while (len > 1) { sum += *p++; len -= 2; }
        if (len) sum += *reinterpret_cast<const uint8_t*>(p);
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    std::vector<uint8_t> TunDevice::BuildUdpPacket(
        IPv4 src_ip, IPv4 dst_ip,
        uint16_t src_port, uint16_t dst_port,
        ConstData payload)
    {
        const std::size_t total = 20 + 8 + payload.size();
        std::vector<uint8_t> pkt(total, 0);

        // IPv4 header
        pkt[0] = 0x45;  // version=4, IHL=5
        uint16_t tlen = HostToNetwork16(static_cast<uint16_t>(total));
        memcpy(&pkt[2], &tlen, 2);
        pkt[8] = 64;    // TTL
        pkt[9] = 17;    // protocol: UDP
        uint32_t src_net = src_ip.ToNetworkOrder();
        uint32_t dst_net = dst_ip.ToNetworkOrder();
        memcpy(&pkt[12], &src_net, 4);
        memcpy(&pkt[16], &dst_net, 4);
        uint16_t ck = IpChecksum({pkt.data(), 20});
        memcpy(&pkt[10], &ck, 2);

        // UDP header
        uint16_t sp = HostToNetwork16(src_port);
        uint16_t dp = HostToNetwork16(dst_port);
        uint16_t ul = HostToNetwork16(static_cast<uint16_t>(8 + payload.size()));
        memcpy(&pkt[20], &sp, 2);
        memcpy(&pkt[22], &dp, 2);
        memcpy(&pkt[24], &ul, 2);
        // UDP checksum = 0 (disabled — legal in IPv4)

        if (!payload.empty())
            memcpy(&pkt[28], payload.data(), payload.size());

        return pkt;
    }

    std::optional<IPv4> TunDevice::ParseDstIP(ConstData packet) {
        if (packet.size() < 20) return std::nullopt;
        return IPv4(packet[16], packet[17], packet[18], packet[19]);
    }

    std::optional<IPv4> TunDevice::ParseSrcIP(ConstData packet) {
        if (packet.size() < 20) return std::nullopt;
        return IPv4(packet[12], packet[13], packet[14], packet[15]);
    }

} // namespace core::network
