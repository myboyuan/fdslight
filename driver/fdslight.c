#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/skbuff.h>
#include<linux/ip.h>
#include<net/udp.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<net/sock.h>
#include<linux/inet.h>
#include<linux/fs.h>
#include<linux/cdev.h>
#include<linux/device.h>
#include<linux/poll.h>
#include<linux/string.h>
#include<linux/slab.h>
#include<linux/errno.h>
#include "fdsl_queue.h"
#include "fdsl_dev_ctl.h"
#include "fdsl_route_table.h"

#define DEV_NAME FDSL_DEV_NAME
#define DEV_CLASS FDSL_DEV_NAME
#define QUEUE_SIZE 10

/* 缓存标志定义 */
#define CACHE_FLAG_IN_TABLE 1    // 路由表中有该数据
#define CACHE_FLAG_NO_TABLE 2 //路由表中没有该数据

struct fdsl_poll{
	struct fdsl_queue *r_queue;
	wait_queue_head_t inq;
};


static struct cdev chr_dev;
static dev_t ndev;
static char flock_flag=0;
static int dev_major;
struct class *dev_class;
static struct file_operations chr_ops;

static struct fdsl_queue *r_queue;

struct fdsl_poll *poll;

static unsigned int subnet=0;
static unsigned int mask=0;

static struct fdsl_route_table *fdsl_whitelist_rt;
// 白名单路由缓存
static struct fdsl_route_cache *fdsl_wl_rc;

static int chr_open(struct inode *node,struct file *f)
{

	int major,minor;
	major=MAJOR(node->i_rdev);
	minor=MINOR(node->i_rdev);
	
	if(flock_flag) return -EBUSY;

	flock_flag=1;
	f->private_data=poll;

	return 0;
}

static int fdsl_set_subnet(unsigned long arg)
{
	struct fdsl_subnet tmp;
	int err=copy_from_user(&tmp,(struct fdsl_subnet *)arg,sizeof(struct fdsl_subnet));

	if(err) return -EINVAL;
	
	mask=0;

	for(int n=0;n<tmp.mask;n++){
		mask|=1<<(31-n);
	}

	subnet=tmp.ipaddr;
	return 0;

}

static int fdsl_add_to_whitelist_table(unsigned long arg)
{
	struct fdsl_subnet tmp;
	int ret=0;
	int err=copy_from_user(&tmp,(struct fdsl_subnet *)arg,sizeof(struct fdsl_subnet));

	if(err) return -EINVAL;

	tmp.ipaddr=ntohl(tmp.ipaddr);

    ret=fdsl_route_table_add(fdsl_whitelist_rt,(unsigned char *)(&tmp.ipaddr),tmp.mask);

	return ret;
}

static int fdsl_whitelist_exists(unsigned long arg)
{
    unsigned int ip4;
    int err=copy_from_user(&ip4,(unsigned int *)arg,sizeof(unsigned int));
    if(err) return -EINVAL;

    ip4=ntohl(ip4);

    return fdsl_route_table_exists(fdsl_whitelist_rt,(unsigned char *)(&ip4));
}

static long chr_ioctl(struct file *f,unsigned int cmd,unsigned long arg)
{
	int ret=0;
	if(_IOC_TYPE(cmd)!=FDSL_IOC_MAGIC) return -EINVAL;

	switch(cmd){
		case FDSL_IOC_SET_SUBNET:
			ret=fdsl_set_subnet(arg);
			break;
		case FDSL_IOC_ADD_WHITELIST_SUBNET:
			ret=fdsl_add_to_whitelist_table(arg);
			break;
		 case FDSL_IOC_WHITELIST_EXISTS:
		    ret=fdsl_whitelist_exists(arg);
		    break;
		default:
			ret=-EINVAL;
			break;
	}

	return ret;
}

static ssize_t chr_read(struct file *f,char __user *u,size_t size,loff_t *loff)
{
	struct fdsl_queue_data *tmp;
	tmp=fdsl_queue_pop(r_queue);

	if (NULL==tmp) return -EAGAIN;

	if(0!=copy_to_user(u,tmp->data,tmp->size)) return -EFAULT;

	return tmp->size;
}

static int chr_release(struct inode *node,struct file *f)
{
	flock_flag=0;
    fdsl_queue_reset(r_queue);

	return 0;
}

static unsigned int chr_poll(struct file *f,struct poll_table_struct *wait)
{
	struct fdsl_poll *p;
	unsigned int mask=0;
	p=f->private_data;
	
	poll_wait(f,&p->inq,wait);
	if(p->r_queue->have) mask|=POLLIN | POLLRDNORM;
	
	return mask;
}

static unsigned int fdsl_push_packet_to_user(struct iphdr *ip_header)
{
    int err,tot_len;
	tot_len=ntohs(ip_header->tot_len);
	err=fdsl_queue_push(r_queue,(char *)ip_header,tot_len);

	if(err) return NF_ACCEPT;

	wake_up_interruptible(&poll->inq);

    return NF_DROP;
}


static unsigned int nf_handle_in(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	struct fdsl_route_cache_data *cdata;
	unsigned short int dport,sport;
	unsigned int saddr,daddr;
	unsigned char protocol;
	int cache_not_exists,table_exists;


	if(!flock_flag) return NF_ACCEPT;
	if(!skb) return NF_ACCEPT;
	
	ip_header=(struct iphdr *)skb_network_header(skb);

	if(!ip_header) return NF_ACCEPT;

	protocol=ip_header->protocol;

	if(IPPROTO_UDP!=protocol) return NF_ACCEPT;

    udp_header=(struct udphdr *)((__u32 *)ip_header+ip_header->ihl);
    dport=ntohs((unsigned short int)udp_header->dest);
    sport=ntohs((unsigned short int)udp_header->source);

    // DNS端口允许通过
    if(53==dport) return NF_ACCEPT;
	if(53==sport) return NF_ACCEPT;

	saddr=htonl((unsigned int)ip_header->saddr);
	daddr=(unsigned int)ip_header->daddr;

	if(subnet!=(mask & saddr)) return NF_ACCEPT;

	// 首先从缓存中查找数据是否存在
    cdata=fdsl_route_cache_find(fdsl_wl_rc,(unsigned char *)(&daddr));
    cache_not_exists=memcmp(cdata->ipaddr,(unsigned char *)(&daddr),4);

    if(!cache_not_exists){
        if(CACHE_FLAG_IN_TABLE==cdata->flags) return NF_ACCEPT;
        if(CACHE_FLAG_NO_TABLE==cdata->flags) return fdsl_push_packet_to_user(ip_header);
    }

    table_exists=fdsl_route_table_exists(fdsl_whitelist_rt,(unsigned char *)(&daddr));

	if(table_exists){
	    fdsl_route_cache_add(fdsl_wl_rc,CACHE_FLAG_IN_TABLE,(unsigned char *)(&daddr));
	    return NF_ACCEPT;
	}

	fdsl_route_cache_add(fdsl_wl_rc,CACHE_FLAG_NO_TABLE,(unsigned char *)(&daddr));

    return fdsl_push_packet_to_user(ip_header);
}

static int create_dev(void)
{
	int ret;
	cdev_init(&chr_dev,&chr_ops);
	ret=alloc_chrdev_region(&ndev,0,1,DEV_NAME);

	if(ret<0) return ret;

	cdev_add(&chr_dev,ndev,1);
	dev_class=class_create(THIS_MODULE,DEV_CLASS);

	if(IS_ERR(dev_class)){
		printk("ERR:failed in creating class\r\n");
		return -1;
	}
	
	dev_major=MAJOR(ndev);
	device_create(dev_class,NULL,ndev,"%s",DEV_NAME);

	return 0;
}

static int delete_dev(void)
{
	cdev_del(&chr_dev);
	device_destroy(dev_class,ndev);
	class_destroy(dev_class);
	unregister_chrdev_region(ndev,0);

	return 0;
}

static struct file_operations chr_ops={
	.owner = THIS_MODULE,
	.open=chr_open,
	.unlocked_ioctl=chr_ioctl,
	.read=chr_read,
	.release=chr_release,
	.poll=chr_poll
};

static struct nf_hook_ops nf_ops={
	.hook=nf_handle_in,
	.hooknum=NF_INET_FORWARD,
	.pf=PF_INET,
	.priority=NF_IP_PRI_FIRST
};

static int fdsl_init(void)
{
	int ret=create_dev();
	if(0!=ret) return ret;
	nf_register_hook(&nf_ops);

	poll=kmalloc(sizeof(struct fdsl_poll),GFP_ATOMIC);
	init_waitqueue_head(&poll->inq);

	r_queue=fdsl_queue_init(QUEUE_SIZE);
	poll->r_queue=r_queue;

	fdsl_whitelist_rt=fdsl_route_table_init(IP_VERSION_4);
	fdsl_wl_rc=fdsl_route_cache_init(IP_VERSION_4);

	return 0;
}

static void fdsl_exit(void)
{
	delete_dev();
	nf_unregister_hook(&nf_ops);
	fdsl_queue_release(r_queue);

	fdsl_route_table_release(fdsl_whitelist_rt);
	fdsl_route_cache_release(fdsl_wl_rc);

	kfree(poll);
}

module_init(fdsl_init);
module_exit(fdsl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fdslight");
MODULE_DESCRIPTION("the module for fdslight");
