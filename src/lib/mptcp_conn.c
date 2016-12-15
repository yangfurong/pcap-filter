#include <mptcp_conn.h>
#include <list.h>
#include <stdlib.h>
#include <string.h>

void init_mptcp_conn(struct mptcp_conn *conn){
    INIT_LIST_HEAD(&(conn->list));
    conn->state = MP_CAP_WAIT;
    conn->match_sf = naive_match_sf;
}

void destroy_mptcp_conn(struct mptcp_conn *conn){
    while(!list_empty(&(conn->list))){
        struct mptcp_sf_node *ptr;
        ptr = list_first_entry(&(conn->list), struct mptcp_sf_node, list);
        list_del(&(ptr->list));
        free(ptr);
    }
}

void add_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf){
    struct mptcp_sf_node *node = 
        (struct mptcp_sf_node*)malloc(sizeof(struct mptcp_sf_node));
    memcpy(&(node->sf), sf, sizeof(*sf));
    list_add(&(node->list), &(conn->list));
}

void del_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf){
    struct mptcp_sf_node *entry = find_sf(conn, sf);
    if(entry != NULL){
        list_del(&(entry->list));
        free(entry);
    }
}

struct mptcp_sf_node* find_sf(struct mptcp_conn *conn, const struct mptcp_sf *sf){
    struct mptcp_sf_node *pos;
    list_for_each_entry(pos, &(conn->list), list){
        if(conn->match_sf(&(pos->sf), sf) != 0){
            return pos; 
        }
    }
    return NULL;
}
