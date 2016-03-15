#ifndef FDSL_DEV_CTL_H
#define FDSL_DEV_CTL_H

struct fdsl_subnet{
	unsigned int ipaddr;
    int mask;	
};

#define FDSL_DEV_NAME "fdslight"
#define FDSL_IOC_MAGIC 0xad

#define FDSL_IOC_SET_SUBNET _IOW(FDSL_IOC_MAGIC,1,int)
#define FDSL_IOC_ADD_WHITELIST_SUBNET _IOW(FDSL_IOC_MAGIC,2,int)

#define FDSL_IOC_ADD_BLACKLIST _IOW(FDSL_IOC_MAGIC,3,int)

// 白名单是否存在
#define FDSL_IOC_WHITELIST_EXISTS _IOW(FDSL_IOC_MAGIC,4,int)
// 黑名单是否存在
#define FDSL_IOC_BLACKLIST_EXISTS _IOW(FDSL_IOC_MAGIC,5,int)

#endif
