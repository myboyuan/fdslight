#include<Python.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include "fdsl_dev_ctl.h"
static PyObject *
fdsl_set_subnet(PyObject *self,PyObject *args)
//设置要执行代理策略的子网
{
	int fileno;
	struct fdsl_subnet tmp;

	if(!PyArg_ParseTuple(args,"iIi",&fileno,&tmp.ipaddr,&tmp.mask)) return NULL;
	
	return PyLong_FromLong(ioctl(fileno,FDSL_IOC_SET_SUBNET,&tmp));
}

static PyObject *
fdsl_add_whitelist_subnet(PyObject *self,PyObject *args)
// UDP白名单模式,在白名单内,将不走代理
{
	int fileno;
	struct fdsl_subnet tmp;

	if(!PyArg_ParseTuple(args,"iIi",&fileno,&tmp.ipaddr,&tmp.mask)) return NULL;

	return PyLong_FromLong(ioctl(fileno,FDSL_IOC_ADD_WHITELIST_SUBNET,&tmp));
}

static PyObject *
fdsl_add_blacklist_subnet(PyObject *self,PyObject *args)
// UDP白名单模式,在白名单内,将不走代理
{
	int fileno;
	struct fdsl_subnet tmp;

	if(!PyArg_ParseTuple(args,"iIi",&fileno,&tmp.ipaddr,&tmp.mask)) return NULL;

	return PyLong_FromLong(ioctl(fileno,FDSL_IOC_ADD_BLACKLIST,&tmp));
}


static PyObject *
fdsl_whitelist_exists(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_WHITELIST_EXISTS,&ip4));
}

static PyObject *
fdsl_blacklist_exists(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_BLACKLIST_EXISTS,&ip4));
}


static PyMethodDef fdsl_ctl_methods[]={
	{"set_subnet",fdsl_set_subnet,METH_VARARGS,"set subnet"},
	{"add_whitelist_subnet",fdsl_add_whitelist_subnet,METH_VARARGS,"set whitelist subnet"},
	{"add_blacklist_subnet",fdsl_add_blacklist_subnet,METH_VARARGS,"set blacklist subnet"},
	{"whitelist_exists",fdsl_whitelist_exists,METH_VARARGS,"whitelist exists"},
	{"blacklist_exists",fdsl_blacklist_exists,METH_VARARGS,"blacklist exists"},
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
