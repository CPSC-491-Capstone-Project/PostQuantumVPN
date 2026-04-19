#include "tunnel.hpp"

#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

/**
 * Open tunnel device file descriptor.
 * @param ifname Tunnel interface name
 * @return -1 on fail. File descriptor on success.
 */
int open_tun(const char* ifname)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    int ret = ioctl(fd, TUNSETIFF, &ifr);
    if (ret < 0) {
        return -1;
    }

    return fd;
}

