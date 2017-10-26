#include<unistd.h>

#ifndef __CSUM_H
#define __CSUM_H


/** calc checksum when ipv4 address change
 * ippkt:ip packet
 * address:new ip address
 * is_source:if non-zero,it will modify dest address,else it will modify source address
 **/
void csum_calc_ipaddr_change(char *ippkt,const char *address,char is_source);

/** calc inrement csum **/
unsigned short csum_calc_inre(unsigned short old_field,unsigned short new_field,unsigned short old_csum);

unsigned short csum_calc(char *buffer,size_t size);

void csum_calc_ip(char *pkt,size_t size);


#endif