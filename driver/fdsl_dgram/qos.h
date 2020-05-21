/** 在系统内核层实现QOS功能 **/
#ifndef FDSL_QOS_H
#define FDSL_QOS_H

#define FDSL_QOS_SLOT_MAX 256

/// 预先分配的QOS槽数量
#define FDSL_QOS_SLOT_ALLOC 4096

/// 流量槽
struct fdsl_qos_slot{
    struct fdsl_qos_slot *begin;
    struct fdsl_qos_slot *end;
    void *data;
};

struct fdsl_qos{
    struct fdsl_qos_slot slots[FDSL_QOS_SLOT_MAX];
    struct fdsl_qos_slot *emptys;
    // 当前已经分配的qos槽数目
    unsigned int slot_alloc_num;
};

int fdsl_qos_slot_init(void);
void fdsl_qos_slot_uninit(void);

/// 把数据包推送到相应的槽位置
int fdsl_qos_put_to_slot(void *iphdr,int is_ipv6);
/// 获取数据包
void *fdsl_qos_get_from_slot(int is_ipv6);

#endif