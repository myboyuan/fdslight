///共享内存块定义
#ifndef MP_NETPKT_SHMBLK_H
#define MP_NETPKT_SHMBLK_H

#include<sys/types.h>

/// 进程块元数据
struct shm_blk_meta{
    // 进程自身的PID
    pid_t my_pid;
    // 对端的进程PID
    pid_t peer_pid;
    // 数据区域块大小
    size_t data_area_block_size;
    // 数据区域块数目
    size_t data_area_block_num;
    // 是否已经知道要读取数据,用于其他进程对本进程的通知
    int is_konwn_read;
};

/// 进程块数据索引对象
struct shm_blk_data_index{

}

#endif