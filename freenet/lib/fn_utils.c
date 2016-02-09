#include <Python.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <net/route.h>
#include <sys/ioctl.h>

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

static PyMethodDef UtilsMethods[] = {
	{"tuntap_create",tuntap_create,METH_VARARGS,"create tuntap device"},
	{"interface_up",tuntap_interface_up,METH_VARARGS,"interface up tuntap "},
	{"set_ipaddr",tuntap_set_ipaddr,METH_VARARGS,"set tuntap ip address"},
	{"tuntap_delete",tuntap_delete,METH_VARARGS,"delete tuntap device ,it equals close"},
	{"calc_incre_csum",calc_incre_csum,METH_VARARGS,"calculate incremental check sum"},
	{NULL,NULL,0,NULL}
};

static struct PyModuleDef utilsmodule = {
	PyModuleDef_HEAD_INIT,
	"tuntap",
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

	m = PyModule_Create(&utilsmodule);

	if (NULL == m) return NULL;

	for (int n = 0; n < const_count; n++) {
		if (PyModule_AddIntConstant(m, const_names[n], const_values[n]) < 0) {
			return NULL;
		}
	}

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
