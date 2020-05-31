

#include "ip.h"
#include "qos.h"

#include "../pywind/clib/netutils.h"


static void __ipv6_handle(struct mbuf *m)
{

}

static void __ipv4_handle(struct mbuf *m)
{
    struct netutil_iphdr *iphdr;
    int version,hdr_len;

    iphdr=(struct netutil_iphdr *)(m->data+m->offset);

    version=(iphdr->ver_and_ihl & 0xf0) >> 4;
    hdr_len=(iphdr->ver_and_ihl & 0x0f) * 4;

    if(4!=version){
        mbuf_pool_put(m);
        return;
    }

    if(hdr_len<20){
        mbuf_pool_put(m);
        return;
    }

    if(m->tail - m->offset < hdr_len){
        mbuf_pool_put(m);
        return;
    }

    qos_handle(m,0);

}

void ip_handle(struct mbuf *m,int is_ipv6)
{
    if(is_ipv6) __ipv6_handle(m);
    else __ipv4_handle(m);
}