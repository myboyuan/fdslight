#ifndef MBUF_H
#define MBUF_H

#include<sys/types.h>

struct mbuf{
    struct mbuf *next;
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

int mbuf_pool_init(struct mbuf_pool *pool,u_int32_t pre_alloc_num);
void mbuf_pool_uninit(struct mbuf_pool *pool);

struct mbuf * mbuf_pool_get(struct mbuf_pool *pool);
void mbuf_pool_put(struct mbuf_pool *pool,struct mbuf *m);

#endif