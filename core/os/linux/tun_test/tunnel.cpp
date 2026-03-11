#include "tunnel.hpp"

int open_tun(const char* ifname) 
{
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(fd, TUNSETIFF, &ifr);
    return fd;
}

