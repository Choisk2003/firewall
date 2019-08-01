#pragma once

#include <stdint.h>

struct icmp_header{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_chSum;
};

struct icmp_iden_seq{
    uint16_t icmp_iden;
    uint16_t icmp_seqNum;
};