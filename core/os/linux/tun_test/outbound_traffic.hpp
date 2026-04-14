#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdio>
#include "tunnel.hpp"
#include <unistd.h>
#include <cstring>

struct network_packet {
    int data_len;
    uint8_t* data;
};

int OutboundTraffic_Read(uint8_t* buf, int buf_len);
int OutboundTraffic_Inject(uint8_t* data, int data_len);
int OutboundTraffic_Init();