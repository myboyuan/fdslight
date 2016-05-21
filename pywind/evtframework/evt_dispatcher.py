#!/usr/bin/env python3

import pywind.evtframework.event as evt_notify
import pywind.evtframework.excepts as excepts
import pywind.lib.timer as timer
from pywind.global_vars import global_vars


class dispatcher(object):
    # handler集合,元素格式为 {fd:handler_object,...}
    __handlers = {}
    __poll = None
    __timer = None

    def __init__(self):
        global_vars["pyw.ioevtfw.dispatcher"] = self

    def create_handler(self, creator_fd, handler, *args, **kwargs):
        """ 创建一个处理者
        :param ns: 命名空间
        :param handler: 处理者
        :return:
        """
        instance = handler()
        fd = instance.init_func(creator_fd, *args, **kwargs)
        self.__handlers[fd] = instance

        return fd

    def delete_handler(self, fd):
        """删除处理者
        :param fd: 文件描述符
        :return:
        """
        if fd not in self.__handlers: return
        if self.__timer.exists(fd): self.__timer.drop(fd)
        handler = self.__handlers[fd]
        handler.delete()
        del self.__handlers[fd]

    def set_timeout(self, fd, seconds):
        if seconds < 0:
            self.__timer.drop(fd)
            return
        self.__timer.set_timeout(fd, seconds)

    def register(self, fd):
        self.__poll.register(fd, evt_notify.EV_TYPE_NO_EV)

    def add_evt_read(self, fd):
        self.__poll.add_event(fd, evt_notify.EV_TYPE_READ)

    def remove_evt_read(self, fd):
        self.__poll.remove_event(fd, evt_notify.EV_TYPE_READ)

    def add_evt_write(self, fd):
        self.__poll.add_event(fd, evt_notify.EV_TYPE_WRITE)

    def remove_evt_write(self, fd):
        self.__poll.remove_event(fd, evt_notify.EV_TYPE_WRITE)

    def unregister(self, fd):
        self.__poll.unregister(fd)

    def myloop(self):
        """重写这个方法,添加你自己需要的循环执行代码"""
        pass

    def ioloop(self, *args, **kwargs):
        """
        :param args: 传递给self.init_func的参数
        :param kwargs: 传递给self.init_func的参数
        :return:
        """

        self.__timer = timer.timer()
        self.init_func(*args, **kwargs)

        while 1:
            wait_time = self.__timer.get_min_time()
            if wait_time < 1: wait_time = 10

            event_set = self.__poll.poll(wait_time)
            self.__handle_events(event_set)
            self.__handle_timeout()
            self.myloop()

        return

    def init_func(self, *args, **kwargs):
        """初始化函数,在调用IOLOOP之前调用,重写这个方法
        :return:
        """
        pass

    def init_func_after_fork(self):
        """fork 之后的第一个调用的函数,此函数只针对POSIX系统,重写这个方法
        :return:
        """
        pass

    def get_handler(self, fd):
        return self.__handlers.get(fd, None)

    def send_message_to_handler(self, src_fd, dst_fd, byte_data):
        if dst_fd not in self.__handlers:
            raise excepts.HandlerNotFoundErr

        handler = self.__handlers[dst_fd]
        handler.message_from_handler(src_fd, byte_data)

        return True

    def handler_exists(self, fd):
        return fd in self.__handlers

    def create_poll(self):
        self.__poll = evt_notify.event()

    def __handle_timeout(self):
        fd_set = self.__timer.get_timeout_names()

        for fd in fd_set:
            if self.__timer.exists(fd): self.__timer.drop(fd)
            if fd in self.__handlers:
                handler = self.__handlers[fd]
                handler.timeout()
            ''''''
        return

    def __handle_events(self, evt_set):
        for fd, evt, udata in evt_set:
            is_read = (evt & evt_notify.EV_TYPE_READ) == evt_notify.EV_TYPE_READ
            is_write = (evt & evt_notify.EV_TYPE_WRITE) == evt_notify.EV_TYPE_WRITE
            is_err = (evt & evt_notify.EV_TYPE_ERR) == evt_notify.EV_TYPE_ERR

            # 别的handler可能删除这个handler,因此需要检查
            if fd not in self.__handlers: continue
            handler = self.__handlers[fd]
            if not self.handler_exists(fd): continue
            if is_err:
                handler.error()
                continue
            if is_read: handler.evt_read()
            if not self.handler_exists(fd): continue
            if is_write: handler.evt_write()
            ''''''
        return

    def ctl_handler(self, src_fd, dst_fd, *args, **kwargs):
        if dst_fd not in self.__handlers:
            raise excepts.HandlerNotFoundErr

        h = self.get_handler(dst_fd)
        return h.handler_ctl(src_fd, *args, **kwargs)
