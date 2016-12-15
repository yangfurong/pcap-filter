#ifndef MPTCP_CONN_H
#define MPTCP_CONN_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <list.h>

//host byte order
struct mptcp_sf{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
}__attribute__((__packed__));

struct mptcp_sf_node{
    struct mptcp_sf sf;
    struct list_head list;
};

enum mptcp_conn_state {
    MP_CAP_WAIT = 0,
    MP_CAP_INIT,
    MP_CAP_READY,
    MP_JOIN_WAIT,
    MP_JOIN_INIT,
    MP_JOIN_READY
};

struct mptcp_conn{
    //linked list of sf
    struct list_head list;
    //state
    enum mptcp_conn_state state;
    int (*match_sf)(struct mptcp_sf *sf, const struct mptcp_sf *cmp_sf);
};

static inline int naive_match_sf(struct mptcp_sf *sf, const struct mptcp_sf *cmp_sf){
    struct mptcp_sf rev_sf;
    rev_sf.src_ip = cmp_sf->dst_ip;
    rev_sf.dst_ip = cmp_sf->src_ip;
    rev_sf.src_port = cmp_sf->dst_port;
    rev_sf.dst_port = cmp_sf->src_port;
    return memcmp(sf, cmp_sf, sizeof(*cmp_sf)) == 0 || 
        memcmp(sf, &rev_sf, sizeof(rev_sf)) == 0;
}

void init_mptcp_conn(struct mptcp_conn *conn);
void destroy_mptcp_conn(struct mptcp_conn *conn);
void add_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf);
void del_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf);
struct mptcp_sf_node* find_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf);

#endif
