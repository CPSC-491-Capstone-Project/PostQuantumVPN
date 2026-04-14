#include "inbound_traffic.hpp"

#define NFQ_QUEUE_ID 0
static struct nfq_state nfq_state = {0};
// static void* inbound_packet_callback;

int InboundTraffic_Inject(struct nfq_packet* packet)
{
    // TODO - fix
    nfq_deliver(packet);
    return 0;
}

int InboundTraffic_Init(void* on_inbound_callback)
{
    return nfq_init(&nfq_state, NFQ_QUEUE_ID, on_inbound_callback);
}

int InboundTraffic_Poll()
{
    return nfq_poll(&nfq_state);
}