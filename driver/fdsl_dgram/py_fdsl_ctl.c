#define PY_SSIZE_T_CLEAN

#include<Python.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include "fdsl_dev_ctl.h"

static PyObject *
fdsl_set_udp_proxy_subnet(PyObject *self,PyObject *args)
{
    int fileno;
    char *sts;
    unsigned char prefix;
    int is_ipv6;
    Py_ssize_t length;

    struct fdsl_subnet subnet;

    if(!PyArg_ParseTuple(args,"iy#Bp",&fileno,&sts,&length,&prefix,&is_ipv6)) return NULL;
    
    if(is_ipv6 && prefix>128) return NULL;
    if(!is_ipv6 && prefix>32) return NULL;

    memcpy(subnet.address,sts,length);
    subnet.prefix=prefix;
    subnet.is_ipv6=is_ipv6;

    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_SET_UDP_PROXY_SUBNET,&subnet));
}

static PyObject *
fdsl_set_tunnel(PyObject *self,PyObject *args)
{
    int fileno,is_ipv6;
    Py_ssize_t length;
    struct fdsl_address address;
    char *sts;

    if(!PyArg_ParseTuple(args,"iy#p",&fileno,&sts,&length,&is_ipv6)) return NULL;
    memcpy(address.address,sts,length);
    address.is_ipv6=is_ipv6;

    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_SET_TUNNEL_IP,&address));
}

static PyMethodDef fdsl_ctl_methods[]={
    {"set_udp_proxy_subnet",fdsl_set_udp_proxy_subnet,METH_VARARGS,"set udp global proxy subnet"},
    {"set_tunnel",fdsl_set_tunnel,METH_VARARGS,"set tunnel"},
	{NULL,NULL,0,NULL}
};

static struct PyModuleDef fdsl_ctl_module={
	PyModuleDef_HEAD_INIT,
	"fdsl_ctl",
	NULL,
	-1,
	fdsl_ctl_methods
};

PyMODINIT_FUNC
PyInit_fdsl_ctl(void)
{
	PyObject *module;

	module=PyModule_Create(&fdsl_ctl_module);
	PyModule_AddStringMacro(module,FDSL_DEV_NAME);

	return module;
}
