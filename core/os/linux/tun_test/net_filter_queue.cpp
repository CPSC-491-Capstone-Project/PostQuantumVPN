#include "net_filter_queue.cpp"


static int on_inbound(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*)
{
    uint8_t* data;
    int len = nfq_get_payload(nfa, &data);
    uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);

    nfq_state->callback(struct nfq_packet {
        .id = id,
        .len = len,
        .data = data,
        .queue_handler = qh
    });

    return 0;
}

int nfq_deliver(struct nfq_packet packet) {
    // NF_ACCEPT delivers the packet to the local socket
    return nfq_set_verdict(packet->queue_handle, packet->id, NF_ACCEPT, packet->len, packet->data);
}

int nfq_init(struct nfq_state* nfq_state, int queue_id, void* callback) 
{
    nfq_state->callback = callback;

    nfq_state->handle = nfq_open();

    nfq_unbind_pf(nfq_state->handle, AF_INET);
    nfq_bind_pf(nfq_state->handle, AF_INET);

    nfq_state->queue_handle = nfq_create_queue(nfq_state->handle, queue_id, on_inbound, nullptr);

    nfq_set_mode(nfq_state->queue_handle, NFQNL_COPY_PACKET, 0xffff);

    nfq_state->socket = nfq_fd(nfq_state->handle);

    return 0;
}

int nfq_poll()
{
    int len = recv(nfq_state->socket, nfq_state->buf, sizeof(nfq_state->buf), 0);

    if (len == 0) {
        return 0;
    }

    if (len < 0) {
        return -1;
    }

    nfq_handle_packet(h, (char*)nfq_state->buf, len);

    return 0;
}
