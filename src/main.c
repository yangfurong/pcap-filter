#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <assert.h>
#include <unistd.h>

#include <tcp_option.h>
#include <mptcp_option.h>
#include <mptcp_conn.h>
#include <list.h>
#include <tcp_utils.h>

//#define DEBUG_INFO

static struct{
#define PCAP_FILE_NAME_LEN 256
    char in_file[PCAP_FILE_NAME_LEN];
    char out_file[PCAP_FILE_NAME_LEN];
}pcap_filter_args;

static void usage(){
    printf("Usage: pcap-filter -f <in-file> -o <out-file>\n");
    exit(-1);
}

static void parse_args(int argc, char **argv){
    char opt;
    int opt_cnt = 0;
    while((opt = getopt(argc, argv, "f:o:")) != -1){
        switch(opt){
            case 'f': 
                strcpy(pcap_filter_args.in_file, optarg); 
                opt_cnt++;
                break;
            case 'o':
                strcpy(pcap_filter_args.out_file, optarg);
                opt_cnt++;
                break;
            default:
                usage();
        }
    }
    if(opt_cnt != 2){
        usage();
    }
}

int main(int argc, char **argv){

    parse_args(argc, argv);

    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_in = pcap_open_offline(pcap_filter_args.in_file, err_buf);
    if(pcap_in == NULL){
        fprintf(stderr, "open pcap file %s failed!\n", pcap_filter_args.in_file);
        exit(-1);
    }

    pcap_dumper_t *pcap_out = pcap_dump_open(pcap_in, pcap_filter_args.out_file);
    if(pcap_out == NULL){
        fprintf(stderr, "open pcap dumper %s failed!\n", pcap_filter_args.out_file);
        exit(-1);
    }

    struct pcap_pkthdr pcap_hdr;
    uint8_t *packet;
    struct mptcp_conn conn;
    uint8_t conn_fin = 0;
    init_mptcp_conn(&conn);

    do{
        packet = pcap_next(pcap_in, &pcap_hdr);
        if(packet != NULL){
            //etherhdr
            //iphdr
            //tcphdr
            //check tcphdr field & mptcp option
            //SYN+MPCAP => initate mptcp connection
            //SYN+MPCAP+ACK => mptcp connection state to ready
            //ACK+MPCAP => mptcp connection established, first subflow established
            //SYN+MPJOIN => initate new sf
            //SYN+ACK+MPJOIN => new sf ready
            //ACK+MPJOIN => new sf added
            //MP-FIN => end 
            struct iphdr *ip_hdr = 
                (struct iphdr*)(packet + sizeof(struct ether_header));
            struct tcphdr *tcp_hdr = 
                (struct tcphdr*)(packet + sizeof(struct ether_header) + 
                        (ip_hdr->ihl << 2));
            struct mptcp_sf sf;
            sf.src_ip = ntohl(ip_hdr->saddr);
            sf.dst_ip = ntohl(ip_hdr->daddr);
            sf.src_port = ntohs(tcp_hdr->th_sport);
            sf.dst_port = ntohs(tcp_hdr->th_dport);
#ifdef DEBUG_INFO
            char src_ip[64], dst_ip[64];
            strcpy(src_ip, inet_ntoa(*(struct in_addr*)(&ip_hdr->saddr)));
            strcpy(dst_ip, inet_ntoa(*(struct in_addr*)(&ip_hdr->daddr)));
            fprintf(stdout, "packet: src(%s:%d), dst(%s:%d)\n",
                    src_ip,
                    sf.src_port,
                    dst_ip,
                    sf.dst_port);
#endif
            if(is_tcp_syn(tcp_hdr) && has_mp_cap(tcp_hdr)){
                add_sf(&conn, &sf);
#ifdef DEBUG_INFO
                fprintf(stdout, "[mp cap]add new subflow!\n");
#endif
            }
            if(is_tcp_syn(tcp_hdr) && has_mp_join(tcp_hdr)){
                add_sf(&conn, &sf);
#ifdef DEBUG_INFO
                fprintf(stdout, "[mp join]add new subflow!\n");
#endif
            }
            if(find_sf(&conn, &sf) != NULL){
                if(has_mp_dss_fin(tcp_hdr)){
                    conn_fin = 1;
#ifdef DEBUG_INFO
                    fprintf(stdout, "connection finished (%s)!\n", pcap_filter_args.in_file);
#endif
                }
                pcap_dump((u_char*)pcap_out, &pcap_hdr, packet);
            }
        }
    }while(packet != NULL && conn_fin == 0);
#ifndef DEBUG_INFO
    if(conn_fin == 0){
        fprintf(stdout, "No MP-FIN founded (%s)!\n", pcap_filter_args.in_file);
    }
#endif

    destroy_mptcp_conn(&conn);

    pcap_dump_flush(pcap_out);
    pcap_dump_close(pcap_out);
    pcap_close(pcap_in);
    return 0;
}

