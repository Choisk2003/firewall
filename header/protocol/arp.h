#pragma once

#include <stdint.h>
#include "ip.h"

#define ARP_ALEN 6

struct __attribute__((aligned(1), packed)) arp_header{
    uint16_t arp_ht;
    uint16_t arp_pt;
    uint8_t arp_hs;
    uint8_t arp_ps;
    uint16_t arp_op;
    uint8_t arp_send[ARP_ALEN];
    ip_addr ip_send;
    uint8_t arp_targ[ARP_ALEN];
    ip_addr ip_targ;
};