#ifndef TCP_UTILS_H
#define TCP_UTILS_H

#define is_tcp_syn(hdr) (hdr->syn)
#define is_tcp_ack(hdr) (hdr->ack)
#define is_tcp_fin(hdr) (hdr->fin)

#endif
