#include <tcp_option.h>
#include <netinet/tcp.h>
#include <stdlib.h>

uint8_t* next_tcp_opt(uint8_t *opt, uint8_t *max, uint8_t kind){
    while(opt < max){
        if(*opt == kind){
            return opt;
        }else if(*opt == TCPOPT_EOL){
            return NULL;
        }else if(*opt == TCPOPT_NOP){
            opt += 1;
        }else{
            opt += *(opt + 1);
        }
    }
    return NULL;
}
