#ifndef QOS_H
#define QOS_H

#include<sys/types.h>

#define QOS_SLOT_SIZE 256

struct qos_slot{
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
    u_int32_t pre_alloc_num;
};

u_int64_t qos_calc_slot(unsigned char *dst_addr,u_int16_t id,int is_ipv6);

int qos_init(struct qos *q,u_int32_t pre_alloc_num);
void qos_uninit(struct qos *q);

int qos_put(struct qos *q,void *data,u_int32_t slot);
void *qos_get(struct qos *q);

#endif