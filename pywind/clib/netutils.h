#include<sys/types.h>

#ifndef __NETUTILS_H
#define __NETUTILS_H

/// 计算掩码
int msk_calc(unsigned char prefix,int is_ipv6,unsigned char *res);
/// 计算子网
int subnet_calc_with_prefix(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res);
int subnet_calc_with_msk(unsigned char *address,unsigned char *msk,int is_ipv6,unsigned char *res);

/** calc inrement csum **/
unsigned short csum_calc_inre(unsigned short old_field,unsigned short new_field,unsigned short old_csum);
unsigned short csum_calc(char *buffer,size_t size);

// 计算广播地址
int net_broadcast_calc(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res);

#endif