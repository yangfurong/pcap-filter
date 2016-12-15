#ifndef MPTCP_OPTION_H
#define MPTCP_OPTION_H

#include <stdint.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>

//tcp option kind
#define TCPOPT_MPTCP 30
//sub type
#define MP_CAP 0x0
#define MP_JOIN 0x1
#define MP_DSS 0x2
#define MP_ADD_ADDR 0x3
#define MP_RM_ADDR 0x4
#define MP_PRIO 0x5
#define MP_FAIL 0x6
#define MP_FASTCLOSE 0x7

static inline uint8_t __subtype(uint8_t *opt){
    return ((*(opt + 2)) >> 4) & 0x0f;
}

uint8_t* next_mptcp_opt(uint8_t *opt, uint8_t *max);


#define IS_FUNC(name) \
int is_mp_##name(uint8_t *opt)

#define IMPL_IS_FUNC(name, type) \
int is_mp_##name(uint8_t *opt){ \
    uint8_t sub_type = __subtype(opt);\
    return sub_type == type; \
}

IS_FUNC(cap);
IS_FUNC(join);
IS_FUNC(dss);
IS_FUNC(add_addr);
IS_FUNC(rm_addr);
IS_FUNC(prio);
IS_FUNC(fail);
IS_FUNC(fastclose);

#define HAS_FUNC(name) \
int has_mp_##name(struct tcphdr *hdr)

#define IMPL_HAS_FUNC(name, type) \
int has_mp_##name(struct tcphdr *hdr){ \
    uint8_t th_off = hdr->th_off; \
    uint8_t *opt = (uint8_t*)hdr + 20; \
    uint8_t *max = (uint8_t*)hdr + (th_off << 2); \
    while(opt != NULL){ \
        opt = next_mptcp_opt(opt, max); \
        if(opt != NULL){ \
            if(is_mp_##name(opt)){ \
                return 1; \
            } \
            opt += *(opt + 1); \
        } \
    } \
    return 0; \
}

HAS_FUNC(cap);
HAS_FUNC(join);
HAS_FUNC(dss);
HAS_FUNC(add_addr);
HAS_FUNC(rm_addr);
HAS_FUNC(prio);
HAS_FUNC(fail);
HAS_FUNC(fastclose);

int has_mp_dss_fin(struct tcphdr *hdr);

#endif
