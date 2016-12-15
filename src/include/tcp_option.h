#ifndef TCP_OPTION_H
#define TCP_OPTION_H

#include <stdint.h>

uint8_t* next_tcp_opt(uint8_t *opt, uint8_t *max, uint8_t kind);

#endif
