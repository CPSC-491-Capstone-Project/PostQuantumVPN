#include "net_filter_queue.hpp"

using core::utils::Logger;

/**
 * Runs as a callback when an inbound traffic is received via nfq_poll()
 * @param qh Net Filter Queue, Queue Handle reference.
 * @param nfa Object holding packet information and data payload.
 * @param callback_data User data for callback, referencing a stateful object for nfq processing.
 * @return -1 on fail, 0 on success.
 */
static int on_inbound(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* callback_data)
{
    struct nfq_state* nfq_state = (struct nfq_state*)callback_data;

    uint8_t* data;
    int len = nfq_get_payload(nfa, &data);
    if (len < 0) {
        Logger::Error("NetFilterQueue: Unable to get payload from nfq_data.");
        return -1;
    }

    uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);

    nfq_state->callback((struct nfq_packet) {
        .packet_id = id,
        .data_len = len,
        .data = data,
        .queue_handler = qh
    });

    return 0;
}

/**
 * Deliver packet to kernel network stack.
 * @param packet Packet to deliver to kernel network stack.
 * @return 0 on successful delivery, -1 on fail.
 */
int nfq_deliver(struct nfq_packet* packet) {
    // NF_ACCEPT delivers the packet to the local socket
    return nfq_set_verdict(packet->queue_handler, packet->packet_id, NF_ACCEPT, packet->data_len, packet->data);
}

/**
 *
 * @param nfq_state Custom stateful instance object for NFQ system
 * @param queue_id ID of NFQ queue to reference.
 * @param callback Callback to be called on inbound packet received (when poll is called).
 * @return -1 on fail, otherwise nfq inbound traffic socket on success.
 */
int nfq_init(struct nfq_state* nfq_state, int queue_id, void* callback)
{
    nfq_state->callback = (nfq_callback_t)callback;

    nfq_state->handle = nfq_open();
    if (nfq_state->handle == NULL) {
        Logger::Error("NetFilterQueue: NFQ handle is NULL.");
        return -1;
    }

    int ret = nfq_unbind_pf(nfq_state->handle, AF_INET); // Evict any existing AF_INET handler.
    if (ret < 0) {
        Logger::Error("NetFilterQueue: Unable to unbind existing AF_INET handler");
        return -1;
    }

    ret = nfq_bind_pf(nfq_state->handle, AF_INET); // Register this process as the AF_INET handler.
    if (ret < 0) {
        Logger::Error("NetFilterQueue: Unable to bind handle to AD_INET");
        return -1;
    }

    nfq_state->queue_handle = nfq_create_queue(nfq_state->handle, queue_id, on_inbound, nfq_state);

    ret = nfq_set_mode(nfq_state->queue_handle, NFQNL_COPY_PACKET, 0xffff);
    if (ret < 0) {
        Logger::Error("NetFilterQueue: Unable to set nfq mode.");
        return -1;
    }

    nfq_state->socket = nfq_fd(nfq_state->handle);

    return nfq_state->socket;
}

/**
 * Poll for inbound network packets.
 * @param nfq_state Stateful object for nfq system.
 * @return -1 on recv failed. 0 on 0 len packet and successfully handled packet.
 */
int nfq_poll(struct nfq_state* nfq_state)
{
    int len = recv(nfq_state->socket, nfq_state->buf, sizeof(nfq_state->buf), 0);

    if (len == 0) {
        return 0;
    }

    if (len < 0) {
        return -1;
    }

    nfq_handle_packet(nfq_state->handle, (char*)nfq_state->buf, len);

    return 0;
}
