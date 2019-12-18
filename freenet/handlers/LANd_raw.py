#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import time, socket


class client(tcp_handler.tcp_handler):
    __creator = None
    __session_id = None

    def init_func(self, creator_fd, address, session_id, is_ipv6=False):
        self.__creator = creator_fd
        self.__session_id = session_id

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_delete(self.__session_id)
        self.unregister(self.fileno)
