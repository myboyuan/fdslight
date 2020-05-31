#ifndef QOS_H
#define QOS_H

#include<sys/types.h>

#include "mbuf.h"

#define QOS_SLOT_SIZE 256

struct qos_slot{
    // 用于对所有可用槽组成一个列表
    struct qos_slot *speed_next;
    struct qos_slot *last;
    struct qos_slot *next;
    void *data;
    /// 所属的槽
    u_int32_t slot;
};

struct qos{
    struct qos_slot *empty_head;
    struct qos_slot *slots[QOS_SLOT_SIZE];

    u_int32_t pre_alloc_num;
    u_int32_t cur_alloc_num;
};


int qos_init(u_int32_t pre_alloc_num);
void qos_uninit(void);

void qos_handle(struct mbuf *m,int is_ipv6);

#endif