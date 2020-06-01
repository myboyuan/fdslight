#include<stdlib.h>
#include<string.h>

#include "../pywind/clib/debug.h"

#include "mbuf.h"

static struct mbuf_pool mbuf_pool;
static int mbuf_pool_is_initialized=0;

int mbuf_pool_init(u_int32_t pre_alloc_num)
{
    struct mbuf *m;
    struct mbuf_pool *pool=&mbuf_pool;

    bzero(pool,sizeof(struct mbuf_pool));

    mbuf_pool_is_initialized=1;

    for(u_int32_t n=0;n<pre_alloc_num;n++){
        m=malloc(sizeof(struct mbuf));
        if(NULL==m){
            STDERR("no memory for pre alloc struct mbuf\r\n");
            mbuf_pool_uninit();
            return -1;
        }

        m->next=pool->empty_head;
        pool->empty_head=m;
    }

    pool->cur_alloc_num=pre_alloc_num;
    pool->pre_alloc_num=pre_alloc_num;

    return 0;
}

void mbuf_pool_uninit(void)
{
    struct mbuf_pool *pool=&mbuf_pool;
    struct mbuf *t,*m=pool->empty_head;

    while(NULL!=m){
        t=m->next;
        free(m);
        m=t;
    }

    mbuf_pool_is_initialized=0;
}

struct mbuf * mbuf_pool_get(void)
{
    struct mbuf *m=NULL;
    struct mbuf_pool *pool=&mbuf_pool;

    if(NULL!=pool->empty_head){
        m=pool->empty_head;
        pool->empty_head=m->next;

        m->next=NULL;

        return m;
    }

    m=malloc(sizeof(struct mbuf));
    if(NULL==m){
        STDERR("no memory for malloc struct mbuf\r\n");
        return NULL;
    }

    STDERR("warning not enough pre alloc mbuf\r\n");

    m->next=NULL;
    pool->cur_alloc_num+=1;

    return m;
}

void mbuf_pool_put(struct mbuf *m)
{
    struct mbuf_pool *pool=&mbuf_pool;
    if(pool->pre_alloc_num > pool->cur_alloc_num){
        ex_free(m);
        pool->cur_alloc_num-=1;
        return;
    }

    m->next=pool->empty_head;
    pool->empty_head=m;
}