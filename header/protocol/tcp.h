#pragma once

#include <stdint.h>

typedef uint32_t tcp_seq;

struct tcp_header
{
    __extension__ union{
	struct
	{
	    uint16_t tcp_src_port;
	    uint16_t tcp_dst_port;
	    tcp_seq th_seq;
	    tcp_seq th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	    uint8_t th_x2:4;
	    uint8_t th_off:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	    uint8_t th_off:4;
	    uint8_t th_x2:4;
#endif
	    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URF 0x20
	    uint16_t th_win;
	    uint16_t th_sum;
	    uint16_t th_urp;
	};
	struct
	{
	    uint16_t source;
	    uint16_t dest;
	    uint32_t seq;
	    uint32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	    uint16_t res1:4;
	    uint16_t doff:4;
	    uint16_t fin:1;
	    uint16_t syn:1;
	    uint16_t rst:1;
	    uint16_t psh:1;
	    uint16_t ack:1;
	    uint16_t urg:1;
	    uint16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	    uint16_t doff:4;
	    uint16_t res1:4;
	    uint16_t res2:2;
	    uint16_t urg:1;
	    uint16_t ack:1;
	    uint16_t psh:1;
	    uint16_t rst:1;
	    uint16_t syn:1;
	    uint16_t fin:1;
#else
#error "adjust your <bits/endian.h> defines"
#endif
	    uint16_t window;
	    uint16_t check;
	    uint16_t urg_ptr;
	};
    };
};