#include<string.h>
#include<stdlib.h>

#include "netutils.h"

int msk_calc(unsigned char prefix,int is_ipv6,unsigned char *res)
{
    unsigned char a,b,constant=0xff;
    unsigned char tables[]={
        0,128,192,224,240,248,252,254
    };

    if(is_ipv6 && prefix>128) return -1;
    if(!is_ipv6 && prefix>32) return -1;

    // 计算出掩码
    a=prefix / 8;
    b=prefix % 8;

    if(is_ipv6) bzero(res,16);
    else bzero(res,4);

    for(int n=0;n<a;n++){
        res[n]=constant;
    }
    
    if(!b) res[a]=tables[b];

    return 0;
}

int subnet_calc_with_prefix(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res)
{
    unsigned char msk[16];
    int rs=msk_calc(prefix,is_ipv6,msk);
    if(rs<0) return -1;

    return subnet_calc_with_msk(address,msk,is_ipv6,res);
}

int subnet_calc_with_msk(unsigned char *address,unsigned char *msk,int is_ipv6,unsigned char *res)
{
    size_t size=4;

    if(is_ipv6) size=16;

    for(size_t n=0;n<size;n++){
        res[n]= address[n] & msk[n];
    }
    return 0;
}

unsigned short csum_calc_inre(unsigned short old_field,unsigned short new_field,unsigned short old_csum)
{
    unsigned long csum = old_csum - (~old_field & 0xFFFF) - new_field ;
    csum = (csum >> 16) + (csum & 0xffff);
    csum +=  (csum >> 16);
    return csum;
}

unsigned short csum_calc(char *buffer,size_t size)
{
    unsigned long sum;
    
    sum = 0;
    while (size > 1) {
            sum += *buffer++;
            size -= 2;
    }

    /*  Add left-over byte, if any */
    if (size)
            sum += *(unsigned char *)buffer;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
            sum  = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}

int net_broadcast_calc(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res)
{
    unsigned char subnet[16],tmp[16];
    unsigned char msk[16],ch;
    int size=4;

    if(subnet_calc_with_prefix(address,prefix,is_ipv6,subnet)<0) return -1;
    msk_calc(prefix,is_ipv6,msk);

    if(is_ipv6) size=16;

    for(int n=0;n<size;n++){
        ch=(unsigned char )((~subnet[n]) & 0xff);
        subnet[n]=ch;

        ch=(unsigned char )((~msk[n]) & 0xff);
        msk[n]=ch;
    }

    subnet_calc_with_msk(subnet,msk,is_ipv6,tmp);

    for(int n=0;n<size;n++){
        ch= (unsigned char)((tmp[n] | address[n]) & 0xff);
        res[n]=ch;    
    }

    return 0;
}