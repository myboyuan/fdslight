#include<Python.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include<fcntl.h>
#include "fdsl_dev_ctl.h"

static PyObject *
fdsl_tf_record_add(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_TF_RECORD_ADD,&ip4));
}

static PyObject *
fdsl_tf_record_del(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_TF_RECORD_DEL,&ip4));
}

static PyObject *
fdsl_tf_find(PyObject *self,PyObject *args)
{
    int fileno;
    unsigned int ip4;

    if(!PyArg_ParseTuple(args,"iI",&fileno,&ip4)) return NULL;
    return PyLong_FromLong(ioctl(fileno,FDSL_IOC_TF_FIND,&ip4));
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
	{"tf_record_add",fdsl_tf_record_add,METH_VARARGS,"add to tcp filter"},
    {"tf_record_del",fdsl_tf_record_del,METH_VARARGS,"delete from tcp filter"},
	{"tf_find",fdsl_tf_find,METH_VARARGS,"find tcp filter record"},
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
