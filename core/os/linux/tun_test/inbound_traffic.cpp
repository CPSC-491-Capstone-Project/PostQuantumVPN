#include "inbound_traffic.hpp"

using core::utils::Logger;

#define NFQ_QUEUE_ID 0
static struct nfq_state nfq_state = {0};

/**
 * Inject inbound packet into kernel's network stack.
 * @param packet Net filter queue packet to inject back into kernel.
 * @return 0 if delivery to kernel was successful otherwise -1.
 */
int InboundTraffic_Inject(struct nfq_packet* packet)
{
    return nfq_deliver(packet);
}

/**
 *
 * @param on_inbound_callback Callback to be called when an inbound packet is received.
 *      Expects: void on_inbound(struct nfq_packet packet)
 * @return Return -1 on init fail, otherwise return socket fild descriptor for inbound traffic.
 */
int InboundTraffic_Init(void* on_inbound_callback)
{
    int ret = nfq_init(&nfq_state, NFQ_QUEUE_ID, on_inbound_callback);
    if (ret < 0) {
        Logger::Error("InboundTraffic: Unable to init NFQ system.");
        return -1;
    }

    return ret;
}

/**
 * Poll for incoming traffic. (Should be called via a polling system such as EPoll.
 * @return 0 on successful packet recv, -1 on fail.
 */
int InboundTraffic_Poll()
{
    return nfq_poll(&nfq_state);
}