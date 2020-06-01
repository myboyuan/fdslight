#ifndef QOS_H
#define QOS_H

#include<sys/types.h>

#include "mbuf.h"

#define QOS_SLOT_SIZE 512

#if QOS_SLOT_SIZE<1
#error The value of QOS_SLOT_SIZE at least
#endif


struct qos_slot{
    // 用于对所有可用槽组成一个列表
    struct qos_slot *speed_next;
    struct mbuf *mbuf_head;
    struct mbuf *mbuf_last;

    int is_used;
};

struct qos{
    struct qos_slot *empty_head;
    struct qos_slot slots[QOS_SLOT_SIZE];

    // 快速定位数据
    struct qos_slot *speed_head;
};

void qos_send(void);

int qos_have_data(void);

int qos_init(void);
void qos_uninit(void);

void qos_handle(struct mbuf *m,int is_ipv6);

#endif