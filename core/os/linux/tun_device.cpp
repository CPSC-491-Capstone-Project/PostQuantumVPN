#include "tun_device.hpp"
#include "logger.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <utility>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

using core::utils::Logger;

namespace core::network {

    TunDevice::~TunDevice() {
        Close();
    }

    TunDevice::TunDevice(TunDevice&& other) noexcept
        : handle_{std::exchange(other.handle_, kInvalidHandle)}
    {}

    TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = std::exchange(other.handle_, kInvalidHandle);
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
        return true;
    }

    void TunDevice::Close() {
        if (IsOpen()) {
            ::close(handle_);
            handle_ = kInvalidHandle;
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

} // namespace core::network
