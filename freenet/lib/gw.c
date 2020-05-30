#define PY_SSIZE_T_CLEAN
#include<Python.h>
#include<structmember.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "../../pywind/clib/debug.h"

#define NETMAP_WITH_LIBS
#include<net/netmap_user.h>

#include "../../gw/mbuf.h"
#include "../../gw/ether.h"
#include "../../gw/qos.h"

#include "../../pywind/clib/netif/tuntap.h"

typedef struct{
    PyObject_HEAD
    struct nm_desc *netmap;
    
    struct mbuf *nm_sent_head;
    struct mbuf *nm_sent_last;
    struct mbuf *tap_sent_head;
    struct mbuf *tap_sent_last;

    int tap_fd;
}fdsl_gw;

static struct nm_desc *__nm_open(const char *if_name)
{
    char name[1024];
    struct nm_desc *netmap;
    int flags;

    sprintf(name,"netmap:%s",if_name);

    if(NULL==netmap){
        STDERR("cannot open %s\r\n",if_name);
        return NULL;
    }

    // 设置为非阻塞模式
    flags=fcntl(netmap->fd,F_GETFL,0);
    fcntl(netmap->fd,F_SETFL,flags | O_NONBLOCK);

    return netmap;
}

void __nm_close(struct nm_desc *d)
{
    nm_close(d);
}

static void
gw_dealloc(fdsl_gw *self)
{
    if(NULL!=self->netmap) nm_close(self->netmap);

    qos_uninit();
    mbuf_pool_uninit();

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

static PyObject *
gw_nm_handle_for_read(PyObject *self,PyObject *args)
{
    int count;
    fdsl_gw *gw=(fdsl_gw *)self;
    struct nm_desc *nm=gw->netmap;
    struct nm_pkthdr h;
    size_t size;
    unsigned char *buf;
    struct mbuf *mbuf;

    if(!PyArg_ParseTuple(args,"i",&count)) return NULL;

    for(int n=0;n<count;n++){
        buf=nm_nexpkt(nm,&h);
        size=h.len;

        if(NULL==buf) break;

        mbuf=mbuf_pool_get();
        if(NULL==mbuf) break;

        mbuf->begin=MBUF_BEGIN;
        mbuf->offset=MBUF_BEGIN;

        memcpy(mbuf->data+mbuf->begin,buf,size);

        mbuf->tail=mbuf->tail+size;
        mbuf->end=mbuf->tail;

        ether_handle(mbuf);
    }

    ioctl(netmap->fd,NIOCRXSYNC,NULL);

    return NULL;
}

static PyObject *
gw_nm_handle_for_write(PyObject *self,PyObject *args)
{



    return NULL;
}

static PyObject *
gw_tap_handle_for_read(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    int fd=gw->tap_fd,count,rs;
    ssize_t read_size;
    struct mbuf *m;

    if(!PyArg_ParseTuple(args,"i",&count)) return NULL;
    
    for(int n=0;n<count;n++){
        m=mbuf_pool_get();
        if(NULL==m) break;

        read_size=read(fd,m->data+MBUF_BEGIN,MBUF_DATA_MAX-MBUF_BEGIN);
        if(read_size < 0) {
            mbuf_pool_put(m);

            if(EAGAIN==errno){
                rs=0;
                break;
            }
        }

        m->begin=MBUF_BEGIN;
        m->offset=m->begin;
        m->tail=m->begin+read_size;
        m->end=m->tail;

        ether_handle(m);
    }

    return NULL;
}

static PyObject *
gw_tap_handle_for_write(PyObject *self,PyObject *args)
{
    return NULL;
}

static PyMethodDef gw_methods[]={
    {"nm_handle_for_read",(PyCFunction)gw_nm_handle_for_read,METH_VARARGS,"handle read for netmap"},
    {"nm_handle_for_write",(PyCFunction)gw_nm_handle_for_write,METH_NOARGS,"handle write for netmap"},
    {"tap_handle_for_read",(PyCFunction)gw_tap_handle_for_read,METH_VARARGS,"handle read for tap device"},
    {"tap_handle_for_write",(PyCFunction)gw_tap_handle_for_write,METH_NOARGS,"handle write for tap device"},
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



