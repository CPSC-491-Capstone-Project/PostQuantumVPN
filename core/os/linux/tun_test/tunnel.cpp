#include "tunnel.hpp"

#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

int open_tun(const char* ifname) 
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(fd, TUNSETIFF, &ifr);
    return fd;
}

