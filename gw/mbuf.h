#ifndef MBUF_H
#define MBUF_H

#include<sys/types.h>

struct mbuf{
    struct mbuf *next;
    // 表示物理网卡
#define MBUF_IF_PHY 0
    // 表示TAP网卡
#define MBUF_IF_TAP 1
    int if_flags;
#define MBUF_BEGIN 128
    u_int32_t begin;
    u_int32_t offset;
    u_int32_t tail;
    u_int32_t end;
#define MBUF_DATA_MAX 0xffff 
    unsigned char data[MBUF_DATA_MAX];
};

struct mbuf_pool{
    struct mbuf *empty_head;

    u_int32_t pre_alloc_num;
    u_int32_t cur_alloc_num;
};

int mbuf_pool_init(u_int32_t pre_alloc_num);
void mbuf_pool_uninit(void);

struct mbuf * mbuf_pool_get(void);
void mbuf_pool_put(struct mbuf *m);

#endif