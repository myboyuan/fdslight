#ifndef MP_NETPKT_PROC_H
#define MP_NETPKT_PROC_H

#include<sys/types.h>

/// 进程块描述
struct proc_block{
    pid_t pid;
    int is_used;
};

#endif