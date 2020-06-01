#include<arpa/inet.h>

#include "ether.h"
#include "ip.h"
#include "mbuf.h"
#include "gw.h"

#include "../pywind/clib/debug.h"

void ether_send(struct mbuf *m)
{
    if(MBUF_IF_PHY==m->if_flags){
        m->if_flags=MBUF_IF_TAP;
    }else{
        m->if_flags=MBUF_IF_PHY;
    }

    send_data(m);
}

void ether_handle(struct mbuf *m)
{
    struct ether_header *header=(struct ether_header *)(m->data+m->begin);
    unsigned short type=ntohs(header->type);

    // 只支持Ethernet II以太网协议
    if(type<0x0800){
        mbuf_pool_put(m);
        return;
    }

    m->offset+=14;

    switch(type){
        // IPv4
        case 0x0800:
            ip_handle(m,0);
            break;
        case 0x86dd:
            ip_handle(m,1);
            break;
        default:
            ether_send(m);
            break;
    }
}