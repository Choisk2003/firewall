#pragma once

#include <stdint.h>

struct udp_header
{
    uint16_t udp_src_port;
    uint16_t udp_dst_port;
    uint16_t udp_l;
    uint16_t udp_chsum;
};