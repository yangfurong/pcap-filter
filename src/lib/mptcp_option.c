#include <tcp_option.h>
#include <mptcp_option.h>

uint8_t* next_mptcp_opt(uint8_t *opt, uint8_t *max){
    return next_tcp_opt(opt, max, TCPOPT_MPTCP);
}

//is_mp_##name(opt)
IMPL_IS_FUNC(cap, MP_CAP)
IMPL_IS_FUNC(join, MP_JOIN)
IMPL_IS_FUNC(dss, MP_DSS)
IMPL_IS_FUNC(add_addr, MP_ADD_ADDR)
IMPL_IS_FUNC(rm_addr, MP_RM_ADDR)
IMPL_IS_FUNC(prio, MP_PRIO)
IMPL_IS_FUNC(fail, MP_FAIL)
IMPL_IS_FUNC(fastclose, MP_FASTCLOSE)

//has_mp_##name(tcphdr)
IMPL_HAS_FUNC(cap, MP_CAP)
IMPL_HAS_FUNC(join, MP_JOIN)
IMPL_HAS_FUNC(dss, MP_DSS)
IMPL_HAS_FUNC(add_addr, MP_ADD_ADDR)
IMPL_HAS_FUNC(rm_addr, MP_RM_ADDR)
IMPL_HAS_FUNC(prio, MP_PRIO)
IMPL_HAS_FUNC(fail, MP_FAIL)
IMPL_HAS_FUNC(fastclose, MP_FASTCLOSE)

//dss fin
int has_mp_dss_fin(struct tcphdr *hdr){
    uint8_t th_off = hdr->th_off; 
    uint8_t *opt = (uint8_t*)hdr + 20; 
    uint8_t *max = (uint8_t*)hdr + (th_off << 2); 
    while(opt != NULL){ 
        opt = next_mptcp_opt(opt, max);
        if(opt != NULL){
            if(is_mp_dss(opt)){
                uint8_t dss_fin = ((*(opt + 3)) >> 4) & 0x1;
                return dss_fin;
            }
            opt += *(opt + 1);
        }
    }
    return 0;
}
