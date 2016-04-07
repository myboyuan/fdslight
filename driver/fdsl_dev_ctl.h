#ifndef FDSL_DEV_CTL_H
#define FDSL_DEV_CTL_H

#define FDSL_DEV_NAME "fdslight"
#define FDSL_IOC_MAGIC 0xad

// 加入TCP过滤记录
#define FDSL_IOC_TF_RECORD_ADD _IOW(FDSL_IOC_MAGIC,1,int)
// 查找tcp过滤记录
#define FDSL_IOC_TF_FIND _IOW(FDSL_IOC_MAGIC,2,int)
// 删除tcp过滤记录
#define FDSL_IOC_TF_RECORD_DEL _IOW(FDSL_IOC_MAGIC,3,int)

// 设置隧道IP
#define FDSL_IOC_SET_TUNNEL_IP _IOW(FDSL_IOC_MAGIC,4,int)




#endif
