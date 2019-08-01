#pragma once

#include <stdint.h>

#define ETH_ALEN 6

#define ETHERTYPE_IP 0x0800 /* IP */
#define ETHERTYPE_ARP 0x0806 /* Address resolution */
#define ETHERTYPE_IPV6 0x86dd /* IP protocol version 6 */

struct ether_header
{
    uint8_t dst[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ether_type;
} __attribute__ ((__packed__));
