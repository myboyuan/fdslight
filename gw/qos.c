
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>

#include "qos.h"
#include "ether.h"

#include "../pywind/clib/sysloop.h"
#include "../pywind/clib/netutils.h"

/// 是否开启游戏优化,开启之后UDP和UDPLite数据包直接发送,不经过重新排序发送
static int qos_game_first=0;
static struct qos qos;
static int qos_is_initialized=0;

static unsigned int __qos_calc_slot(unsigned char *dst_addr,u_int8_t protocol,u_int16_t id,int is_ipv6)
{
    unsigned char buf[4];
    unsigned int *v;

    buf[0]=dst_addr[0];
    buf[1]=protocol;
    
    memcpy(buf+2,&id,2);

    v=(unsigned int *)buf;

    return (*v) % QOS_SLOT_SIZE;
}

static int __qos_put(void *data,u_int32_t slot)
{
    



    return 0;
}

static void *__qos_get(void)
{
    return NULL;
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
    
    slot=__qos_calc_slot(header->dst_addr,header->protocol,port,0);

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
    
    slot=__qos_calc_slot(header->dst_addr,header->next_header,port,1);

    if(slot<0){
        mbuf_pool_put(m);
        return;
    }

    if(__qos_put(m,slot)){
        mbuf_pool_put(m);
        return;
    }
}

int qos_init(u_int32_t pre_alloc_num)
{

    bzero(&qos,sizeof(struct qos));
    qos_is_initialized=1;

    for(u_int32_t n=0;n<pre_alloc_num;n++){
        

    }


    return 0;
}

void qos_uninit(void)
{
    if(!qos_is_initialized) return;
}

void qos_handle(struct mbuf *m,int is_ipv6)
{
    if(is_ipv6) __qos_handle_ipv6(m);
    else __qos_handle_ip(m);
}
