#!/usr/bin/env python3
"""本地进程消息"""

import pywind.evtframework.handler.tcp_handler as tcp_handler
import pywind.proc.lib.msg_socket as msg_socket
import socket


class _msg_base(tcp_handler.tcp_handler):
    def msg_readable(self, message):
        """重写这个方法"""
        pass

    def evt_read(self):
        try:
            return super(_msg_base, self).evt_read()
        except msg_socket.MsgSocketWantReadErr:
            pass

    def handle_tcp_received_data(self, received_data):
        pass


class _msgs(_msg_base):
    def init_func(self, fileno, cs, address):
        cs = msg_socket.wrap_socket(cs)

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def msg_readable(self, message):
        """重写这个方法"""
        pass


class msgd(_msg_base):
    """本地进程消息服务端"""

    def init_func(self, fileno, addr_family, address):
        s = socket.socket(addr_family, socket.SOCK_STREAM)
        s = msg_socket.wrap_socket(s)

        self.set_socket(s)
        self.bind(address)

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)


class msgc(_msg_base):
    """本地进程消息客户端"""

    def init_func(self, fileno, addr_family, address):
        s = socket.socket(addr_family, socket.SOCK_STREAM)
        s = msg_socket.wrap_socket(s)

        self.set_socket(s)
        self.connect(address, 5)

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def msg_readable(self, message):
        """重写这个方法"""
        pass
