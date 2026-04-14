#pragma once

#include "net_filter_queue.hpp"

int InboundTraffic_Init(void* on_inbound_callback);
int InboundTraffic_Poll();