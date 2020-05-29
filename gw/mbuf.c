#include<stdlib.h>
#include<string.h>

#include "../pywind/clib/debug.h"

#include "mbuf.h"

int mbuf_pool_init(struct mbuf_pool *pool,u_int32_t pre_alloc_num)
{
    struct mbuf *m;

    bzero(pool,sizeof(struct mbuf_pool));

    for(u_int32_t n=0;n<pre_alloc_num;n++){
        m=malloc(sizeof(struct mbuf));
        if(NULL==m){
            STDERR("no memory for pre alloc struct mbuf\r\n");
            mbuf_pool_uninit(pool);
            return -1;
        }

        m->next=pool->empty_head;
        pool->empty_head=m;
    }

    pool->cur_alloc_num=pre_alloc_num;
    pool->pre_alloc_num=pre_alloc_num;

    return 0;
}

void mbuf_pool_uninit(struct mbuf_pool *pool)
{
    struct mbuf *t,*m=pool->empty_head;

    while(NULL!=m){
        t=m->next;
        free(m);
        m=t;
    }
}

struct mbuf * mbuf_pool_get(struct mbuf_pool *pool)
{
    struct mbuf *m=NULL;

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

    m->next=NULL;
    pool->cur_alloc_num+=1;

    return m;
}

void mbuf_pool_put(struct mbuf_pool *pool,struct mbuf *m)
{
    if(pool->pre_alloc_num > pool->cur_alloc_num){
        free(m);
        pool->cur_alloc_num-=1;
        return;
    }

    m->next=pool->empty_head;
    pool->empty_head=m;
}