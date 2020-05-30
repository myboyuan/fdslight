#include<arpa/inet.h>

#include "ether.h"
#include "ip.h"

void ether_handle(struct mbuf *m)
{
    struct ether_header *header=(struct ether_header *)(m->data+m->begin);
    unsigned short type=ntohs(header->type);

    switch(type){
        // IPv4
        case 0x0800:
            ip_handle(m,0);
            break;
        case 0x86dd:
            ip_handle(m,1);
            break;
        // 直接发送到tap设备
        default:
            break;
    }
}