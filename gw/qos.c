

#include<stdlib.h>

#include "qos.h"
#include "gw.h"

#include "../pywind/clib/sysloop.h"

static int64_t __qos_calc_slot(unsigned char *dst_addr,u_int16_t id,int is_ipv6)
{
    return -1;
}

static int __qos_put(void *data,u_int32_t slot)
{
    return 0;
}

static void *__qos_get(void)
{
    return NULL;
}

int qos_init(u_int32_t pre_alloc_num)
{
    return 0;
}

void qos_uninit(void)
{
    
}


void qos_handle(struct mbuf *m,int is_ipv6)
{
    send_data(m);
}
