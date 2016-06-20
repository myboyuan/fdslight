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
#include<linux/version.h>
#include "fdsl_queue.h"
#include "fdsl_dev_ctl.h"
#include "fdsl_ip_filter.h"

#define DEV_NAME FDSL_DEV_NAME
#define DEV_CLASS FDSL_DEV_NAME
#define QUEUE_SIZE 10

#define COPY_IP_FROM_USER  err=copy_from_user(&ui_tmp,(unsigned long *)arg,sizeof(unsigned int));if(err) return -EINVAL;ui_tmp=ntohl(ui_tmp);

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
static struct fdsl_ip_filter *dst_ip_filter;

struct fdsl_poll *poll;

static unsigned int tunnel=0;

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

static int fdsl_set_tunnel(unsigned long arg)
{
	int err=copy_from_user(&tunnel,(unsigned long *)arg,sizeof(unsigned int));
	if(err) return -EINVAL;

    tunnel=htonl(tunnel);
	return 0;
}

static long chr_ioctl(struct file *f,unsigned int cmd,unsigned long arg)
{
	int ret=0,err=0;
	unsigned int ui_tmp;
	if(_IOC_TYPE(cmd)!=FDSL_IOC_MAGIC) return -EINVAL;

	switch(cmd){
        case FDSL_IOC_TF_RECORD_ADD:
			COPY_IP_FROM_USER;
            ret=fdsl_ip_filter_add(dst_ip_filter,(const char *)(&ui_tmp));
            break;
        case FDSL_IOC_TF_RECORD_DEL:
   			COPY_IP_FROM_USER;
             ret=fdsl_ip_filter_delete(dst_ip_filter,(const char *)(&ui_tmp));
             break;
        case FDSL_IOC_TF_FIND:
       		COPY_IP_FROM_USER;
            ret=fdsl_ip_filter_find(dst_ip_filter,(const char *)(&ui_tmp));
            break;
        case FDSL_IOC_SET_TUNNEL_IP:
            ret=fdsl_set_tunnel(arg);
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

static unsigned int hanle_udp_in(struct iphdr *ip_header)
// 处理UDP
{
    unsigned short sport,dport;
	struct udphdr *udp_header;

    udp_header=(struct udphdr *)((__u32 *)ip_header+ip_header->ihl);
    dport=ntohs((unsigned short int)udp_header->dest);
    sport=ntohs((unsigned short int)udp_header->source);
	
	if(53==dport) return NF_ACCEPT;
	if(53==sport) return NF_ACCEPT;

    return fdsl_push_packet_to_user(ip_header);
}

static unsigned int handle_sctp_in(struct iphdr *ip_header)
// 处理SCTP协议
{
    return fdsl_push_packet_to_user(ip_header);
}

static unsigned int handle_ip_and_icmp_in(struct iphdr *ip_header)
// TCP和ICMP处理
{
    unsigned int daddr;
	int find_r=0;

	daddr=(unsigned int)ip_header->daddr;
    find_r=fdsl_ip_filter_find(dst_ip_filter,(const char *)(&daddr));

	if (find_r < 1) return NF_ACCEPT;

    return fdsl_push_packet_to_user(ip_header);
}

static unsigned int nf_handle_in(
// 处理流进的包
#if LINUX_VERSION_CODE<=KERNEL_VERSION(3,1,2)
        unsigned int hooknum,
#endif
#if LINUX_VERSION_CODE>=KERNEL_VERSION(4,4,0)
        void *priv,
#else
        const struct nf_hook_ops *ops,
#endif
		struct sk_buff *skb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
        const struct nf_hook_state *state
#else
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)
#endif
		)
{
	struct iphdr *ip_header;
	unsigned char protocol;
	unsigned int daddr;

	if(!flock_flag) return NF_ACCEPT;
	if(!skb) return NF_ACCEPT;

	ip_header=(struct iphdr *)skb_network_header(skb);

	if(!ip_header) return NF_ACCEPT;
	daddr=(unsigned int)ip_header->daddr;

	if (daddr==tunnel) return NF_ACCEPT;

	protocol=ip_header->protocol;
	switch(protocol){
	    case IPPROTO_UDP:
	        return hanle_udp_in(ip_header);
	    case IPPROTO_TCP:
	        return handle_ip_and_icmp_in(ip_header);
	    case IPPROTO_ICMP:
	        return handle_ip_and_icmp_in(ip_header);
        case IPPROTO_SCTP:
            return handle_sctp_in(ip_header);
	    default:return NF_ACCEPT;
	}
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
    dst_ip_filter=fdsl_ip_filter_init(FDSL_IP_VER4);
	poll->r_queue=r_queue;


	return 0;
}

static void fdsl_exit(void)
{
	delete_dev();
	nf_unregister_hook(&nf_ops);
	fdsl_queue_release(r_queue);
    fdsl_ip_filter_release(dst_ip_filter);
    
	kfree(poll);
}

module_init(fdsl_init);
module_exit(fdsl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fdslight");
MODULE_DESCRIPTION("the module for fdslight");
