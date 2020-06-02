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
#include "../../gw/gw.h"

#include "../../pywind/clib/netif/tuntap.h"

typedef struct{
    PyObject_HEAD

    struct nm_desc *netmap;

    int tap_fd;
    char tap_name[512];
}fdsl_gw;

static PyObject *ev_notify_cb=NULL;
static int netmap_write_flags=0;
static int tap_write_flags=0;

static struct mbuf *nm_sent_head=NULL;
static struct mbuf *nm_sent_last=NULL;

static struct mbuf *tap_sent_head=NULL;
static struct mbuf *tap_sent_last=NULL;

static struct nm_desc *__nm_open(const char *if_name)
{
    char name[1024];
    struct nm_desc *netmap;
    int flags;

    sprintf(name,"netmap:%s",if_name);

    netmap=nm_open(name,NULL,0,0);

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

    tapdev_close(self->tap_fd,self->tap_name);

    // 注意这里和mbuf的uninit顺序不能调,QOS可能会保存一部分mbuf
    // 所以要先释放qos再释放mbuf
    qos_uninit();
    mbuf_pool_uninit();

    Py_DECREF(ev_notify_cb);

    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
gw_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    u_int32_t pre_alloc_mbuf;
    fdsl_gw *self;
    struct nm_desc *netmap;
    PyObject *cb;

    const char *tap_name;
    const char *if_name;
    char tap_name2[512];
    int flags,is_err;

    tap_name2[0]='\0';

    Py_XDECREF(ev_notify_cb);

    if(!PyArg_ParseTuple(args,"ssIO:set_callback",&if_name,&tap_name,&pre_alloc_mbuf,&cb)) return NULL;
    

    if(!PyCallable_Check(cb)){
        PyErr_SetString(PyExc_TypeError,"parameter must be callback");
        return NULL;
    }

    is_err=mbuf_pool_init(pre_alloc_mbuf);
    if(is_err){
        STDERR("cannot initialized mbuf pool\r\n");
        return NULL;
    }

    is_err=qos_init();
    if(is_err){
        STDERR("cannot initialized qos\r\n");
        return NULL;
    }


    self=(fdsl_gw *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;

    strcpy(tap_name2,tap_name);

    netmap=__nm_open(if_name);
    if(NULL==netmap){
        Py_TYPE(self)->tp_free((PyObject *) self);
        STDERR("cannot open if_name %s for netmap\r\n",if_name);

        qos_uninit();
        mbuf_pool_uninit();
        return NULL;
    }

    self->tap_fd=tapdev_create(tap_name2);
    if(self->tap_fd<0){
        Py_TYPE(self)->tp_free((PyObject *) self);
        STDERR("cannot create tap device %s\r\n",tap_name2);

        __nm_close(netmap);

        qos_uninit();
        mbuf_pool_uninit();

        return NULL;
    }

    tapdev_up(tap_name2);
    
    strcpy(self->tap_name,tap_name2);

    self->netmap=netmap;
    
    nm_sent_head=NULL;
    nm_sent_last=NULL;
    
    tap_sent_head=NULL;
    tap_sent_last=NULL;

    flags=fcntl(self->tap_fd,F_GETFL,0);
    fcntl(self->tap_fd,F_SETFL,flags | O_NONBLOCK);
    
    Py_INCREF(cb);
    ev_notify_cb=cb;

    return (PyObject *)self;
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
        buf=nm_nextpkt(nm,&h);
        size=h.len;

        if(NULL==buf) break;

        mbuf=mbuf_pool_get();
  
        if(NULL==mbuf) break;

        mbuf->begin=MBUF_BEGIN;
        mbuf->offset=MBUF_BEGIN;

        memcpy(mbuf->data+mbuf->begin,buf,size);

        mbuf->tail=mbuf->tail+size;
        mbuf->end=mbuf->tail;

        mbuf->if_flags=MBUF_IF_PHY;

        ether_handle(mbuf);
    }

    ioctl(nm->fd,NIOCRXSYNC,NULL);

    Py_RETURN_TRUE;
}

static PyObject *
gw_nm_handle_for_write(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    struct mbuf *m;
    int r;
    PyObject *f=ev_notify_cb,*arglist,*cb_rs,*b;

    // 此处调用回调函数取消事件
    if(NULL==nm_sent_last){
        netmap_write_flags=0;
        b=PyBool_FromLong(0);

        DBG_FLAGS;
        arglist=Py_BuildValue("(ssN)","netmap","write",b);
        cb_rs=PyObject_CallObject(f,arglist);
        DBG_FLAGS;

        Py_DECREF(b);
        Py_DECREF(arglist);
        Py_XDECREF(cb_rs);

        Py_RETURN_TRUE;
    }

    while(1){
        m=nm_sent_head;
        if(NULL==m) break;

        r=nm_inject(gw->netmap,m->data+m->begin,m->end-m->begin);
        if(r<1) break;
        nm_sent_head=m->next;
        if(NULL==nm_sent_head) nm_sent_last=NULL;

        mbuf_pool_put(m);
    }

    Py_RETURN_TRUE;
}

static PyObject *
gw_tap_handle_for_read(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    int fd=gw->tap_fd,count;
    ssize_t read_size;
    struct mbuf *m;

    if(!PyArg_ParseTuple(args,"i",&count)) return NULL;
    
    for(int n=0;n<count;n++){
        m=mbuf_pool_get();
        if(NULL==m) break;

        read_size=read(fd,m->data+MBUF_BEGIN,MBUF_DATA_MAX-MBUF_BEGIN);
        if(read_size < 0) {
            mbuf_pool_put(m);

            if(EAGAIN==errno) break;
            else {Py_RETURN_FALSE;}
        }

        m->begin=MBUF_BEGIN;
        m->offset=m->begin;
        m->tail=m->begin+read_size;
        m->end=m->tail;

        m->if_flags=MBUF_IF_TAP;

        ether_handle(m);
    }

    Py_RETURN_TRUE;
}

static PyObject *
gw_tap_handle_for_write(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    struct mbuf *m;
    ssize_t r;
    PyObject *f=ev_notify_cb,*arglist,*cb_rs,*b;

    // 此处调用回调函数取消事件
    if(NULL==tap_sent_last){
        tap_write_flags=0;
        b=PyBool_FromLong(0);
        arglist=Py_BuildValue("(ssN)","tap","write",b);
        DBG_FLAGS;
        cb_rs=PyObject_CallObject(f,arglist);
        DBG_FLAGS;

        Py_DECREF(b);
        Py_DECREF(arglist);
        Py_XDECREF(cb_rs);
        DBG_FLAGS;
  
        Py_RETURN_TRUE;
    }

    DBG_FLAGS;

    while(1){
        m=tap_sent_head;
        if(NULL==m) break;
        

        r=write(gw->tap_fd,m->data+m->begin,m->end-m->begin);
        
        if(r<0){
            if(EAGAIN==errno) break;
            Py_RETURN_FALSE;
        }

        tap_sent_head=m->next;
        if(NULL==tap_sent_head) tap_sent_last=NULL;
        mbuf_pool_put(m);
    }

    Py_RETURN_TRUE;
}

static PyObject *
gw_tap_fd(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    return PyLong_FromLong(gw->tap_fd);
}

static PyObject *
gw_netmap_fd(PyObject *self,PyObject *args)
{
    fdsl_gw *gw=(fdsl_gw *)self;
    return PyLong_FromLong(gw->netmap->fd);
}

static PyObject *
gw_qos_have_data(PyObject *self,PyObject *args)
{
    return PyBool_FromLong(qos_have_data());
}

static PyObject *
gw_qos_send(PyObject *self,PyObject *args)
{
    qos_send();
    Py_RETURN_NONE;
}

void send_data(struct mbuf *m)
{
    PyObject *f=ev_notify_cb,*arglist,*result,*b;
    int *flags;
    const char *name,*ev_name="write";
    const char *names[]={"netmap","tap"};

    if(NULL==m) return;
    m->next=NULL;

    if(MBUF_IF_PHY==m->if_flags){
        flags=&netmap_write_flags;
        name=names[0];

        if(NULL!=nm_sent_last){
            nm_sent_last->next=m;
        }else{
            nm_sent_head=m;
        }

        nm_sent_last=m;


    }else{
        flags=&tap_write_flags;
        name=names[1];

        if(NULL!=tap_sent_last){
            tap_sent_last->next=m;
        }else{
            tap_sent_head=m;
        }

        tap_sent_last=m;
    }

    // 已经加入过写事件那么不再加入该事件
    if(*flags) return;

    *flags=1;

    b=PyBool_FromLong(1);
    arglist=Py_BuildValue("(ssN)",name,ev_name,b);
    result=PyObject_CallObject(f,arglist);

    Py_DECREF(b);
    Py_DECREF(arglist);
    Py_XDECREF(result);
    DBG_FLAGS;
}

static PyMethodDef gw_methods[]={
    {"nm_handle_for_read",(PyCFunction)gw_nm_handle_for_read,METH_VARARGS,"handle read for netmap"},
    {"nm_handle_for_write",(PyCFunction)gw_nm_handle_for_write,METH_NOARGS,"handle write for netmap"},
    {"tap_handle_for_read",(PyCFunction)gw_tap_handle_for_read,METH_VARARGS,"handle read for tap device"},
    {"tap_handle_for_write",(PyCFunction)gw_tap_handle_for_write,METH_NOARGS,"handle write for tap device"},
    {"tap_fd",(PyCFunction)gw_tap_fd,METH_NOARGS,"get tap device fileno"},
    {"netmap_fd",(PyCFunction)gw_netmap_fd,METH_NOARGS,"get netmap device fileno"},
    {"qos_have_data",(PyCFunction)gw_qos_have_data,METH_NOARGS,"check if all data have been sent"},
    {"qos_send",(PyCFunction)gw_qos_send,METH_NOARGS,"send data from qos"},
    {NULL}
};

static PyTypeObject gw_type={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_new=gw_new,
    .tp_dealloc=(destructor)gw_dealloc,
    .tp_name="gw",
    .tp_doc="gateway module for python",
    .tp_basicsize=sizeof(fdsl_gw),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
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



