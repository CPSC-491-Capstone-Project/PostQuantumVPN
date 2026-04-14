#include "inbound_traffic.hpp"

using core::utils::Logger;

#define NFQ_QUEUE_ID 0
static struct nfq_state nfq_state = {0};
// static void* inbound_packet_callback;

int InboundTraffic_Inject(struct nfq_packet* packet)
{
    return nfq_deliver(packet);
}

int InboundTraffic_Init(void* on_inbound_callback)
{
    int ret = nfq_init(&nfq_state, NFQ_QUEUE_ID, on_inbound_callback);
    if (ret < 0) {
        Logger::Error("InboundTraffic: Unable to init NFQ system.");
        return -1;
    }

    return 0;
}

int InboundTraffic_Poll()
{
    return nfq_poll(&nfq_state);
}