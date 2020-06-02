
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>

#include "qos.h"
#include "ether.h"

#include "../pywind/clib/netutils.h"
#include "../pywind/clib/debug.h"

/// 是否开启游戏优化,开启之后UDP和UDPLite数据包直接发送,不经过重新排序发送
static int qos_game_first=0;
static struct qos qos;
static int qos_is_initialized=0;
static int qos_num_for_calc=0;

static unsigned int __qos_calc_slot(unsigned char *addr,u_int8_t protocol,u_int16_t id,int is_ipv6)
{
    unsigned char buf[4];
    unsigned int *v;

    buf[0]=addr[0];
    buf[1]=protocol;
    
    memcpy(buf+2,&id,2);

    v=(unsigned int *)buf;

    return (*v) % qos_num_for_calc;
}

static int __qos_put(struct mbuf *m,u_int32_t slot)
{
    struct qos_slot *s=&(qos.slots[slot]);
    
    // 非常重要,否则会出现段错误
    m->next=NULL;

    if(s->is_used){
        s->mbuf_last->next=m;
        s->mbuf_last=m;

        return 0;
    }

    bzero(s,sizeof(struct qos_slot));
    s->is_used=1;

    s->mbuf_head=m;
    s->mbuf_last=m;

    s->speed_next=qos.speed_head;
    qos.speed_head=s;

    return 0;
}

static void __qos_handle_ip(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    struct netutil_udphdr *udphdr=NULL;
    struct netutil_tcphdr *tcphdr=NULL;
    unsigned short port;
    unsigned int slot;
    int hdr_len= (header->ver_and_ihl & 0x0f)*4;
    unsigned char *data=m->data+m->offset+hdr_len;

    if((17==header->protocol || 136==header->protocol) && qos_game_first){
        ether_send(m);
        return;
    }

    if(6==header->protocol){
        tcphdr=(struct netutil_tcphdr *)data;
        port=ntohs(tcphdr->dst_port);
    }else if (17==header->protocol || 136==header->protocol){
        udphdr=(struct netutil_udphdr *)data;
        port=ntohs(udphdr->dst_port);
    }else{
        port=0;
    }
    
    slot=__qos_calc_slot(header->src_addr,header->protocol,port,0);

    if(__qos_put(m,slot)){
        mbuf_pool_put(m);
        return;
    }
}

static void __qos_handle_ipv6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct netutil_udphdr *udphdr=NULL;
    struct netutil_tcphdr *tcphdr=NULL;
    unsigned int slot;
    unsigned short port;
    unsigned char *data=m->data+m->offset+40;
    
    if((17==header->next_header || 136==header->next_header) && qos_game_first){
        ether_send(m);
        return;
    }

    if(6==header->next_header){
        tcphdr=(struct netutil_tcphdr *)data;
        port=ntohs(tcphdr->dst_port);
    }else if (17==header->next_header || 136==header->next_header){
        udphdr=(struct netutil_udphdr *)data;
        port=ntohs(udphdr->dst_port);
    }else{
        port=0;
    }
    
    slot=__qos_calc_slot(header->src_addr,header->next_header,port,1);

    if(__qos_put(m,slot)){
        mbuf_pool_put(m);
        return;
    }
}

void qos_send(void)
{
    struct qos_slot *slot,*old;
    struct mbuf *mbuf;

    slot=qos.speed_head;
    old=qos.speed_head;

    while(NULL!=slot){
        mbuf=slot->mbuf_head;
        slot->mbuf_head=mbuf->next;

        if(NULL!=slot->mbuf_head){
            old=slot;
            slot=slot->speed_next;
            ether_send(mbuf);
            continue;
        }

        ether_send(mbuf);

        slot->is_used=0;

        if(slot==qos.speed_head){
            qos.speed_head=slot->speed_next;
            old=qos.speed_head;
            slot=slot->speed_next;
            continue;
        }

        old->speed_next=slot->speed_next;
        slot=slot->speed_next;
    }

}

int qos_have_data(void)
{
    int rs=NULL==qos.speed_head?0:1;

    return rs;
}

int qos_init(void)
{
    bzero(&qos,sizeof(struct qos));
    qos_is_initialized=1;

    if(0==QOS_SLOT_SIZE%2) qos_num_for_calc=QOS_SLOT_SIZE-1;


    return 0;
}

void qos_uninit(void)
{
    struct qos_slot *slot;
    struct mbuf *m,*t;
    

    if(!qos_is_initialized) return;

    for(int n=0;n<QOS_SLOT_SIZE;n++){
        slot=&(qos.slots[n]);
        if(!slot->is_used) continue;

        m=slot->mbuf_head;
        while(NULL!=m){
            t=m->next;
            mbuf_pool_put(m);
            m=t;
        }
    }

    qos_is_initialized=0;

}

void qos_handle(struct mbuf *m,int is_ipv6)
{
    if(is_ipv6) __qos_handle_ipv6(m);
    else __qos_handle_ip(m);

    qos_send();
}

