#ifndef FDSL_DEV_CTL_H
#define FDSL_DEV_CTL_H

#define FDSL_DEV_NAME "fdslight_dgram"
#define FDSL_IOC_MAGIC 0xad


// 打开UDP代理功能
#define FDSL_IOC_OPEN_UDPPROXY _IOW(FDSL_IOC_MAGIC,1,int)

// 打开TCP不可靠功能(uTCP)
#define FDSL_IOC_OPEN_uTCP _IOW(FDSL_IOC_MAGIC,2,int)

// 设置全局UDP代理的局域网机器
#define FDSL_IOC_SET_UDP_PROXY_SUBNET _IOW(FDSL_IOC_MAGIC,3,int)
// 设置隧道IP
#define FDSL_IOC_SET_TUNNEL_IP _IOW(FDSL_IOC_MAGIC,4,int)


struct fdsl_subnet{
    char address[16];
    // 目的端口
    unsigned short dport;
    unsigned char prefix;
    char is_ipv6;
};

struct fdsl_address{
    char address[16];
    char is_ipv6;
};


#endif
