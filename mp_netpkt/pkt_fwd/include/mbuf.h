#ifndef MP_NETPKT_MBUF_H
#define MP_NETPKT_MBUF_H

#include<sys/types.h>

struct mbuf{
    struct mbuf *next;
    union{
        unsigned short link_proto;
        unsigned char ip_proto;
    };
    char pad[2];
#define MBUF_BEGIN 128
    unsigned int begin;
    unsigned int offset;
    unsigned int tail;
    unsigned int end;
#define MBUF_DATA_MAX 3072
    unsigned char data[MBUF_DATA_MAX];
};



#endif