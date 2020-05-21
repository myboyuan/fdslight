
#include "qos.h"

static struct fdsl_qos fdsl_qos;
static int fdsl_qos_is_initialized=0;

int fdsl_qos_slot_init(void)
{
    return 0;
}

void fdsl_qos_slot_uninit(void)
{
    if(!fdsl_qos_is_initialized) return;

    
}

/// 把数据包推送到相应的槽位置
int fdsl_qos_put_to_slot(void *iphdr,int is_ipv6)
{
    return 0;
}


void *fdsl_qos_get_from_slot(int is_ipv6)
{

}