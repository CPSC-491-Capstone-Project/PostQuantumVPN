#pragma once

#include "net_filter_queue.hpp"
#include "temp/logger.hpp"

int InboundTraffic_Init(void* on_inbound_callback);
int InboundTraffic_Inject(struct nfq_packet* packet);
int InboundTraffic_Poll();