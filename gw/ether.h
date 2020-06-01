#ifndef ETHER_H
#define ETHER_H

#include "mbuf.h"

struct ether_header{
    unsigned char dst_hwaddr[6];
    unsigned char src_hwaddr[6];
    union
    {
        unsigned short type;
        unsigned short length;
    };
};

void ether_send(struct mbuf *m);
void ether_handle(struct mbuf *m);

#endif