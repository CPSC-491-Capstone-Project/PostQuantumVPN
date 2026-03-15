#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define MTU 1500

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open(/dev/net/tun)");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* IFF_NO_PI: no extra packet info header */
    if (dev && *dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

static void bring_up(const char *dev)
{
    char cmd[128];

    /* Assign an IP and bring the link up */
    snprintf(cmd, sizeof(cmd), "ip addr add 10.0.0.1/24 dev %s", dev);
    if (system(cmd) != 0)
        fprintf(stderr, "Warning: failed to assign IP (are you root?)\n");

    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", dev);
    if (system(cmd) != 0)
        fprintf(stderr, "Warning: failed to bring link up\n");

    printf("Interface %s is up at 10.0.0.1/24\n", dev);
    printf("Try: ping 10.0.0.2  (from another terminal)\n\n");
}

int main(void)
{
    char dev[IFNAMSIZ] = "tun0";
    unsigned char buf[MTU];
    ssize_t nread;
    int fd;

    fd = tun_alloc(dev);
    if (fd < 0) {
        fprintf(stderr, "Failed to allocate TUN device\n");
        return 1;
    }
    printf("TUN device '%s' opened (fd=%d)\n", dev, fd);

    bring_up(dev);

    /* Keep fd open and read packets — closing fd destroys the interface */
    printf("Reading packets (Ctrl+C to quit)...\n");
    while ((nread = read(fd, buf, sizeof(buf))) > 0) {
        /* First byte of IP header: version in upper nibble */
        int ip_version = (buf[0] >> 4) & 0xF;
        printf("Received %zd byte IPv%d packet\n", nread, ip_version);
    }

    if (nread < 0)
        perror("read");

    close(fd);
    return 0;
}
