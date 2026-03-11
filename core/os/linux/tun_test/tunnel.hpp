#pragma once

#include <linux/if_tun.h>

int open_tun(const char* ifname);