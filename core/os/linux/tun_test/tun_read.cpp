#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int open_tun(const char* ifname) {
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(fd, TUNSETIFF, &ifr);
    return fd;
}

// Raw socket for injecting processed outbound packets back into the kernel.
// SO_MARK=1 matches the fwmark rule in vpn-up.sh which routes via main table,
// so the packet goes out through the physical interface instead of looping back to tun0.
int open_raw_socket() {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { perror("socket SOCK_RAW"); return -1; }

    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int mark = 1;
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

    return fd;
}

void inject_outbound(int raw_fd, uint8_t* buf, int len) {
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr, buf + 16, 4);  // dst IP from IPv4 header bytes 16-19
    sendto(raw_fd, buf, len, 0, (struct sockaddr*)&dst, sizeof(dst));
}

static int on_inbound(struct nfq_q_handle* qh, struct nfgenmsg*,
                      struct nfq_data* nfa, void*)
{
    uint8_t* data;
    int len = nfq_get_payload(nfa, &data);
    uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);

    std::cout << "INBOUND  " << len << " bytes\n";

    // --- do something with data here ---

    // NF_ACCEPT delivers the packet to the local socket
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, data);
}

int main() {
    int tun_fd  = open_tun("tun0");
    int raw_fd  = open_raw_socket();

    struct nfq_handle*   h  = nfq_open();
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    struct nfq_q_handle* qh = nfq_create_queue(h, 0, on_inbound, nullptr);
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    int nfq_sock = nfq_fd(h);

    uint8_t buf[65536];

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_fd,  &fds);
        FD_SET(nfq_sock, &fds);
        select(std::max(tun_fd, nfq_sock) + 1, &fds, nullptr, nullptr, nullptr);

        if (FD_ISSET(tun_fd, &fds)) {
            int len = read(tun_fd, buf, sizeof(buf));
            std::cout << "OUTBOUND " << len << " bytes\n";

            // --- do something with buf here ---

            // Inject back via raw socket with fwmark=1 → bypasses vpn_out → goes to main table → physical interface
            inject_outbound(raw_fd, buf, len);
        }

        if (FD_ISSET(nfq_sock, &fds)) {
            int len = recv(nfq_sock, buf, sizeof(buf), 0);
            nfq_handle_packet(h, (char*)buf, len);
        }
    }
}
