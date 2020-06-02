#ifndef IP_H
#define IP_H

#include "mbuf.h"


void ip_handle(struct mbuf *m,int is_ipv6);


#endif