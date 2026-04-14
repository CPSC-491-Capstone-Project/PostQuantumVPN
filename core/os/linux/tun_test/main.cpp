#include <array>
#include <csignal>
#include <cstdio>
#include <iostream>

#include "inbound_traffic.hpp"
#include "outbound_traffic.hpp"
#include "temp/event_poller.hpp"
#include "temp/logger.hpp"

using core::network::EventPoller;
using core::network::EventMask;
using core::network::PollEvent;
using core::network::Handle;
using core::utils::Logger;

static volatile bool g_running = true;

static void OnSignal(int) {
    g_running = false;
}

static void on_inbound(struct nfq_packet packet) {
    printf("INBOUND: Read packet of length: %d\n", packet.data_len);

    InboundTraffic_Inject(&packet);
}

static void HandleInbound() {
    InboundTraffic_Poll();
}

static void HandleOutbound() {
    static uint8_t buf[65536];

    const int len_recv = OutboundTraffic_Read(buf, sizeof(buf));
    if (len_recv < 0) {
        perror("Unable to read outbound packet!\n");
        return;
    }

    printf("OUTBOUND: Read packet of length: %d\n", len_recv);

    const int ret = OutboundTraffic_Inject(buf, len_recv);
    if (ret < 0) {
        perror("Unable to inject outbound traffic!\n");
    }
}

int main() {
    std::signal(SIGINT,  OnSignal);
    std::signal(SIGTERM, OnSignal);

    core::utils::Logger::getInstance().init(std::cerr);

    const Handle nfq_fd = InboundTraffic_Init((void*)on_inbound);
    if (nfq_fd < 0) {
        perror("Failed to Init inbound traffic!");
        return 1;
    }

    const Handle tunnel_fd = OutboundTraffic_Init();
    if (tunnel_fd < 0) {
        perror("Failed to Init outbound traffic!");
        return 1;
    }

    EventPoller poller;
    if (!poller.Open()) {
        return 1;
    }

    const uint32_t interest = EventMask::Readable
                            | EventMask::Error
                            | EventMask::Hangup;

    if (!poller.Add(nfq_fd, interest) || !poller.Add(tunnel_fd, interest)) {
        return 1;
    }

    std::array<PollEvent, 8> events{};

    while (g_running) {
        const int ready = poller.Poll(std::span{events}, 100);
        if (ready < 0) {
            break;
        }

        for (int i = 0; i < ready; ++i) {
            const Handle fd   = events[i].handle;
            const auto   mask = events[i].mask;

            if (mask & (EventMask::Error | EventMask::Hangup)) {
                g_running = false;
                break;
            }

            if (mask & EventMask::Readable) {
                if (fd == nfq_fd) {
                    HandleInbound();
                } else if (fd == tunnel_fd) {
                    HandleOutbound();
                }
            }
        }
    }

    return 0;
}
