#include <Python.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<structmember.h>

#define TUN_DEV_NAME "fdslight"

/* 增量式校检和 */
static unsigned short csum_incremental_update_modified(unsigned short old_csum,
                unsigned short old_field,
                unsigned short new_field)

{
   unsigned long csum = old_csum - (~old_field & 0xFFFF) - new_field ;
   csum = (csum >> 16) + (csum & 0xffff);
   csum +=  (csum >> 16);
   return csum;
}

/* 计算校检和 */
static unsigned short calc_checksum(unsigned short *buffer,int size)
{
    unsigned long cksum=0;
    while (size>1){
        cksum+=*buffer++;
        size-=sizeof(unsigned short);
    }
    if(size){
        cksum+=*(unsigned char *)buffer;
    }
    cksum=(cksum >>16)+(cksum & 0xffff);
    cksum+=(cksum >>16);

    return (unsigned short)(~cksum);
}

/**
 * 激活接口
 */
static int
interface_up(char *interface_name)
{
	int s;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}

	struct ifreq ifr;
	strcpy(ifr.ifr_name, interface_name);

	short flag;
	flag = IFF_UP;
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
	{
		return -1;
	}

	ifr.ifr_ifru.ifru_flags |= flag;

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
	{
		return -1;
	}

	return 0;

}
/** 获取网卡IP地址 **/
int get_nc_ip(const char *eth, char *ipaddr)
{
	int sock_fd;
	struct  sockaddr_in my_addr;
	struct ifreq ifr;

	/**//* Get socket file descriptor */
	if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
	{
		return -1;
	}

	/**//* Get IP Address */
	strncpy(ifr.ifr_name, eth, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ-1]='\0';

	if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0)
	{
		return -2;
	}

	memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
	strcpy(ipaddr, inet_ntoa(my_addr.sin_addr));
	close(sock_fd);
	return 0;
}

/**
 *  设置接口ip地址
 */
static int
set_ipaddr(char *interface_name, char *ip)
{
	int s;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}

	struct ifreq ifr;
	strcpy(ifr.ifr_name, interface_name);

	struct sockaddr_in addr;
	bzero(&addr, sizeof(struct sockaddr_in));
	addr.sin_family = PF_INET;
	inet_aton(ip, &addr.sin_addr);

	memcpy(&ifr.ifr_ifru.ifru_addr, &addr, sizeof(struct sockaddr_in));

	if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
	{
		return -1;
	}

	return 0;
}

/**
 *  创建接口
 */
static int
tun_create(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;

	if (*dev != '\0')
	{
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
	{
		close(fd);
		return -1;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/**
 *  增加到x.x.x.x的路由
 *  同命令:route add x.x.x.x dev tun0
 */

static PyObject *
tuntap_create(PyObject *self, PyObject *args)
{

	char *dev_name;
	int ret, flags;

	if (!PyArg_ParseTuple(args, "si", &dev_name, &flags)) {
		return NULL;
	}

	ret = tun_create(dev_name, flags);
	return PyLong_FromLong(ret);
}

static PyObject *
tuntap_interface_up(PyObject *self, PyObject *args)
{
	char *interface;
	int ret;

	if (!PyArg_ParseTuple(args, "s", &interface))
		return NULL;

	ret = interface_up(interface);

	return ret < 0 ? Py_False : Py_True;
}

static PyObject *
tuntap_set_ipaddr(PyObject *self, PyObject *args)
{
	char *interface_name, *ip;
	int ret;

	if (!PyArg_ParseTuple(args, "ss", &interface_name, &ip))
		return NULL;

	ret = set_ipaddr(interface_name, ip);
	return ret < 0 ? Py_False : Py_True;
}

static PyObject *
tuntap_delete(PyObject *self, PyObject *args)
{
	int fd;

	if (!PyArg_ParseTuple(args, "i", &fd))
		return NULL;

	close(fd);

	return Py_None;
}


static PyObject *
calc_incre_csum(PyObject *self,PyObject *args)
{
    unsigned short old_csum,old_field,new_field,ret;
    if(!PyArg_ParseTuple(args,"HHH",&old_csum,&old_field,&new_field)){
        return NULL;
    }

    ret=csum_incremental_update_modified(old_csum,old_field,new_field);

    return PyLong_FromLong(ret);
}

static PyObject *
calc_csum(PyObject *self,PyObject *args)
{
    const char *sts;
    int size=0;
    unsigned short int csum;
    if(!PyArg_ParseTuple(args,"y#i",&sts,&size)) return NULL;

    csum=calc_checksum((unsigned short *)sts,size);

    return PyLong_FromLong(csum);
}

static PyObject *
get_netcard_ip(PyObject *self,PyObject *args)
{
    const char *eth_name;
    char eth_ip[20];
    int err;
    if (!PyArg_ParseTuple(args, "s", &eth_name)) return NULL;
    err=get_nc_ip(eth_name,eth_ip);
    if(err) return Py_None;

    return Py_BuildValue("s",eth_ip);
}

static PyMethodDef UtilsMethods[] = {
	{"tuntap_create",tuntap_create,METH_VARARGS,"create tuntap device"},
	{"interface_up",tuntap_interface_up,METH_VARARGS,"interface up tuntap "},
	{"set_ipaddr",tuntap_set_ipaddr,METH_VARARGS,"set tuntap ip address"},
	{"tuntap_delete",tuntap_delete,METH_VARARGS,"delete tuntap device ,it equals close"},
	{"calc_incre_csum",calc_incre_csum,METH_VARARGS,"calculate incremental checksum"},
	{"calc_csum",calc_csum,METH_VARARGS,"calculate checksum"},
	{"get_nc_ip",get_netcard_ip,METH_VARARGS,"get netcard ip address"},
	{NULL,NULL,0,NULL}
};

//---
// 分配到的数据内存大小
#define MBUF_AREA_SIZE 1501

// mbuf
typedef struct {
    PyObject_HEAD
    unsigned short payload_size;
    unsigned short offset;
    char data_area[MBUF_AREA_SIZE];
} mbuf;

static PyObject *
mbuf_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    mbuf *self;
    self = (mbuf *)type->tp_alloc(type, 0);
    
    return (PyObject *)self;
}

static int
mbuf_init(mbuf *self, PyObject *args, PyObject *kwds)
{
    memset(self->data_area,0,MBUF_AREA_SIZE);
	self->offset=0;

    return 0;
}

static void 
mbuf_dealloc(mbuf *self)
{
    return;
}

static PyMemberDef mbuf_members[]={
    {"payload_size",T_USHORT,offsetof(mbuf,payload_size),0,"payload_size"},
    {"offset",T_USHORT,offsetof(mbuf,offset),0,"data offset"},
    {NULL}
};

static PyObject *
mbuf_reset(mbuf *self)
{
    memset(self->data_area,0,MBUF_AREA_SIZE);
    self->payload_size=0;
	self->offset=0;

    Py_RETURN_NONE;
}

static PyObject *
mbuf_copy2buf(mbuf *self,PyObject *args)
{
    const char *sts;
    int length;

    if(!PyArg_ParseTuple(args,"y#",&sts,&length)) return NULL;
    if(length > MBUF_AREA_SIZE) return NULL;

    memcpy(self->data_area,sts,length);
    self->payload_size=length;

    Py_RETURN_NONE;
}

static PyObject *
mbuf_ip_version(mbuf *self)
{
    unsigned int ip_ver=(self->data_area[0] & 0xf0) >>4;

    return PyLong_FromLong(ip_ver);
}


static PyObject *
mbuf_get_data(mbuf *self)
{
	int t=self->payload_size-self->offset;
	const char *ptr;
	if(t<0) return NULL;

	ptr=self->data_area+self->offset;

    return Py_BuildValue("y#",ptr,t);
}

static PyObject *
mbuf_get_part(mbuf *self,PyObject *args)
{
	unsigned short length;
	const char *ptr;
	int t=self->payload_size-self->offset;

	if(t<0) return NULL;
	if(!PyArg_ParseTuple(args,"H",&length)) return NULL;
	
	if(length>t) length=t;

	ptr=self->data_area+self->offset;

	if(1==length) return Py_BuildValue("B",ptr[0]);

	return Py_BuildValue("y#",ptr,length);
}

static PyObject *
mbuf_replace(mbuf *self,PyObject *args)
{
	const char *sts;
	char *ptr;
	int length;

	int t=self->payload_size-self->offset;

	if(!PyArg_ParseTuple(args,"y#",&sts,&length)) return Py_True;
	if(t<length) return Py_False;
	
	ptr=self->data_area+self->offset;

	//printf("%s\r\n",sts);
	memcpy(ptr,sts,length);

	return Py_True;
}

static PyMethodDef mbuf_methods[]={
    {"reset", (PyCFunction)mbuf_reset, METH_NOARGS,"reset data buff to zero"},
    {"copy2buf",(PyCFunction)mbuf_copy2buf,METH_VARARGS,"copy data to buff"},
    {"get_data",(PyCFunction)mbuf_get_data,METH_NOARGS,"get data from buff"},
    {"ip_version",(PyCFunction)mbuf_ip_version,METH_NOARGS,"get ip version"},
	{"replace",(PyCFunction)mbuf_replace,METH_VARARGS,"replace buffer content"},
	{"get_part",(PyCFunction)mbuf_get_part,METH_VARARGS,"get part data"},
    {NULL}
};


static PyTypeObject mbuf_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "fn_utils.mbuf",             /* tp_name */
    sizeof(mbuf),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)mbuf_dealloc,  /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,          /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "memory buff for ipdata",           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    mbuf_methods,             /* tp_methods */
    mbuf_members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)mbuf_init,      /* tp_init */
    0,                         /* tp_alloc */
    mbuf_new,                 /* tp_new */
};	

static struct PyModuleDef utilsmodule = {
	PyModuleDef_HEAD_INIT,
	"fn_utils",
	NULL,
	-1,
	UtilsMethods
};


PyMODINIT_FUNC
PyInit_fn_utils(void)
{
	PyObject *m;

	const char *const_names[] = {
		"IFF_TUN",
		"IFF_TAP",
		"IFF_NO_PI",

		"TUN_PI_SIZE",
		"TUN_PI_FLAGS_SIZE",
		"TUN_PI_PROTO_SIZE",
	};

	const int const_values[] = {
		IFF_TUN,
		IFF_TAP,
		IFF_NO_PI,

		sizeof(struct tun_pi),
		sizeof(__u16),
		sizeof(__be16)
	};

	int const_count = sizeof(const_names) / sizeof(NULL);
	
	mbuf_type.tp_new = PyType_GenericNew;

	if (PyType_Ready(&mbuf_type) < 0)
        return NULL;

	m = PyModule_Create(&utilsmodule);

	Py_INCREF(&mbuf_type);

	if (NULL == m) return NULL;

	for (int n = 0; n < const_count; n++) {
		if (PyModule_AddIntConstant(m, const_names[n], const_values[n]) < 0) {
			return NULL;
		}
	}

    PyModule_AddObject(m, "mbuf", (PyObject *)&mbuf_type);
	PyModule_AddStringMacro(m,TUN_DEV_NAME);
    PyModule_AddIntConstant(m, "MBUF_AREA_SIZE",MBUF_AREA_SIZE);

	return m;

}

/**
   int main(int argc, char *argv[])
   {
   int tun, ret;
   char tun_name[IFNAMSIZ];
   unsigned char buf[4096];
   unsigned char ip[4];

   tun_name[0] = '/0';
   tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
   if (tun < 0)
   {
   return 1;
   }
   printf("TUN name is %s/n", tun_name);

		//激活虚拟网卡增加到虚拟网卡的路由
		interface_up(tun_name);
		route_add(tun_name);

		while (1) {

		ret = read(tun, buf, sizeof(buf));
		printf("read %d bytes/n", ret);
		int i;
		for(i=0;i<ret;i++)
		{
		printf("%02x ",buf[i]);
		}
		printf("/n");
		if (ret < 0)
		break;
		memcpy(ip, &buf[12], 4);
		memcpy(&buf[12], &buf[16], 4);
		memcpy(&buf[16], ip, 4);
		buf[20] = 0;
 *((unsigned short*)&buf[22]) += 8;
 ret = write(tun, buf, ret);
 printf("write %d bytes/n", ret);
 }

 return 0;
 }**/
