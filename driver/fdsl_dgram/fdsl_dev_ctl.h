#ifndef FDSL_DEV_CTL_H
#define FDSL_DEV_CTL_H

#define FDSL_DEV_NAME "fdslight_dgram"
#define FDSL_IOC_MAGIC 0xad

// 设置全局UDP代理的局域网机器
#define FDSL_IOC_SET_UDP_PROXY_SUBNET _IOW(FDSL_IOC_MAGIC,1,int)
// 设置隧道IP
#define FDSL_IOC_SET_TUNNEL_IP _IOW(FDSL_IOC_MAGIC,2,int)

struct fdsl_subnet{
    char address[16];
    unsigned char prefix;
    char is_ipv6;
};

struct fdsl_address{
    char address[16];
    char is_ipv6;
};

#endif
