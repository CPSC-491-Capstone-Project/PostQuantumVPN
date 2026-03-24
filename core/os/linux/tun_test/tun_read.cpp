#include "tun_read.hpp"


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

static int on_inbound(struct nfq_packet packet) 
{
    // Modify data here.

    std::cout << "INBOUND " << packet.data_len << " bytes\n";

    
    // Deliver data to desination socket.
    return nfq_deliver(&packet);
}

int main() {
    int tun_fd  = open_tun("tun0");
    int raw_fd  = open_raw_socket();

    struct nfq_state nfq_state = {0};

    int ret = nfq_init(&nfq_state, 0, (void*)on_inbound);

    uint8_t buf[65536];

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tun_fd,  &fds);
        FD_SET(nfq_state.socket, &fds);
        select(std::max(tun_fd, nfq_state.socket) + 1, &fds, nullptr, nullptr, nullptr);

        if (FD_ISSET(tun_fd, &fds)) {
            int len = read(tun_fd, buf, sizeof(buf));
            std::cout << "OUTBOUND " << len << " bytes\n";

            // --- do something with buf here ---

            // Inject back via raw socket with fwmark=1 → bypasses vpn_out → goes to main table → physical interface
            inject_outbound(raw_fd, buf, len);
        }

        nfq_poll(&nfq_state);
    }
}
