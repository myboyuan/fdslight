#define PY_SSIZE_T_CLEAN
#include<Python.h>
#include<structmember.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "../../clib/debug.h"

#define NETMAP_WITH_LIBS
#include<net/netmap_user.h>

#include "../../gw/mbuf.h"
#include "../../gw/ether.h"
#include "../../gw/qos.h"

typedef struct{
    PyObject_HEAD
    struct nm_desc *netmap;
    struct mbuf_pool pool;
    struct qos qos;
}fdsl_gw;

static void
gw_dealloc(fdsl_gw *self)
{
    if(NULL!=self->netmap) nm_close(self->netmap);

    qos_uninit(&(self->qos));
    mbuf_pool_uninit(&(self->pool));

    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
gw_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    u_int32_t pre_alloc_mbuf,pre_alloc_qos_slot;
    fdsl_gw *self;
    struct nm_desc *netmap;

    const char *tap_name;
    const char *if_name;
    char tap_name2[512];

    tap_name2[0]='\0';

    self=(fdsl_gw *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;

    if(!PyArg_ParseTuple(args,"ssII",&tap_name,&if_name,&pre_alloc_mbuf,&pre_alloc_qos_slot)){
        Py_TYPE(self)->tp_free((PyObject *) self);
        return NULL;
    }

    return NULL;
}


static PyMethodDef gw_methods[]={
    {NULL}
};

static PyTypeObject gw_type={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_new=gw_new,
    .tp_dealloc=(destructor)gw_dealloc,
    .tp_name="gw",
    .tp_doc="gw",
    .tp_basicsize=sizeof(fdsl_gw),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT,
    .tp_methods=gw_methods
};

static PyModuleDef gw_module={
    PyModuleDef_HEAD_INIT,
    "gw",
    "gateway module",
    -1,
    NULL
};

PyMODINIT_FUNC
PyInit_gw(void){
    PyObject* m;

    if (PyType_Ready(&gw_type) < 0) return NULL;

    m = PyModule_Create(&gw_module);
    if (m == NULL) return NULL;

    Py_INCREF(&gw_type);
    PyModule_AddObject(m, "gw", (PyObject *)&gw_type);

    return m;
}



