#include<Python.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include "fdsl_dev_ctl.h"

static PyObject *
fdsl_set_udp_proxy_subnet(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;
    unsigned char prefix;
    struct fdsl_subnet subnet;

    if(!PyArg_ParseTuple(args,"iIc",&fileno,&ip4,&prefix)) return NULL;

    subnet.address=ip4;
    subnet.prefix=prefix;

    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_SET_UDP_PROXY_SUBNET,&subnet));
}

static PyObject *
fdsl_set_tunnel(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_SET_TUNNEL_IP,&ip4));
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
