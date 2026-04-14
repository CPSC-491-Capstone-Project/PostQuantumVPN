#include "outbound_traffic.hpp"

#include <cstddef>

using core::utils::Logger;

static int outbound_injection_fd = -1;
static int outbound_interception_fd = -1;

// #include <fcntl.h>

// Raw socket for injecting processed outbound packets back into the kernel.
// SO_MARK=1 matches the fwmark rule in vpn-up.sh which routes via main table,
// so the packet goes out through the physical interface instead of looping back to tun0.
static int open_raw_socket() {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        Logger::Error("OutboundTraffic: Unable to open socket");
        return -1;
    }

    // Provides the full IP header.
    int one = 1;
    int ret = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (ret < 0) {
        Logger::Error("OutboundTraffic: Unable to set socket option: IP_HDRINCL");
        return -1;
    }

    // Firewall mark to mark packets as processed by application.
    int mark = 1;
    ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (ret < 0) {
        Logger::Error("OutboundTraffic: Unable to set socket option: SO_MARK");
        return -1;
    }

    return fd;
}

int OutboundTraffic_Inject(uint8_t* data, int data_len)
{
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr, data + 16, 4);  // dst IP from IPv4 header bytes 16-19

    int bytes_sent = sendto(outbound_injection_fd, data, data_len, 0, (struct sockaddr*)&dst, sizeof(dst));
    if (bytes_sent < 0) {
        return -1;
    }

    return bytes_sent;
}

int OutboundTraffic_Read(uint8_t* buf, int buf_len)
{
    int len = read(outbound_interception_fd, buf, buf_len);

    if (len < 0) {
        return -1;
    }

    return len;
}

int OutboundTraffic_Init()
{
    int injection_fd = open_raw_socket();
    if (injection_fd < 0) {
        Logger::Error("OutboundTraffic: Unable to open outbound traffic injection socket.");
        return -1;
    }

    int tun_fd  = open_tun("tun0");
    if (tun_fd < 0) {
        Logger::Error("OutboundTraffic: Unable to open tunnel socket.");
        return -1;
    }

    outbound_injection_fd = injection_fd;
    outbound_interception_fd = tun_fd;

    return tun_fd;
}