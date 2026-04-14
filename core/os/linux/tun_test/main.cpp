#include <iostream>

#include "inbound_traffic.hpp"
#include "outbound_traffic.hpp"


#include <thread>
#include <chrono>

static int on_inbound(struct nfq_packet packet)
{
    // Modify data here.

    printf("INBOUND: Read packet of length: %d\n", packet.data_len);


    // Deliver data to desination socket.
    return nfq_deliver(&packet);
}

int main()
{
    int ret = InboundTraffic_Init((void*)on_inbound);
    if (ret < 0) {
        perror("Failed to Init inbound traffic!");
    }

    ret = OutboundTraffic_Init();
    if (ret < 0) {
        perror("Failed to Init outbound traffic!\n");
    }

    const int buf_len = 65536;
    uint8_t buf[buf_len];

    while (true) {
        InboundTraffic_Poll();
        int len_recv = OutboundTraffic_Read(buf, buf_len);
        if (len_recv < 0) {
            perror("Unable to read outbound packet!\n");
        } else {
            printf("OUTBOUND: Read packet of length: %d\n", len_recv);
            ret = OutboundTraffic_Inject(buf, len_recv);
            if (ret < 0) {
                perror("Unable to inject outbound traffic!\n");
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}