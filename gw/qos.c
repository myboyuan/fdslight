

#include<stdlib.h>

#include "qos.h"
#include "gw.h"

#include "../pywind/clib/sysloop.h"

/// 是否开启UDP优先
static int qos_udp_first=0;
static struct qos qos;
static int qos_is_initialized=0;

static int64_t __qos_calc_slot(unsigned char *dst_addr,u_int8_t protocol,u_int16_t id,int is_ipv6)
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
    if(!qos_is_initialized) return;
}


void qos_handle(struct mbuf *m,int is_ipv6)
{
    send_data(m);
}
