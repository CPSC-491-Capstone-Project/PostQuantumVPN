#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdbool.h>

struct nfq_state {
    struct nfq_handle* handle;
    struct nfq_q_handle* queue_handle;
    void* callback;
    int socket;

    uint8_t buf[65536];
}

struct nfq_packet {
    uint32_t packet_id, 
    int data_len,
    uint8_t* data,
    struct nfq_q_handle* queue_handler
}

int nfq_init(struct nfq_state* nfq_state, int queue_id, void* callback);
int nfq_poll();
int nfq_deliver(struct nfq_packet packet);