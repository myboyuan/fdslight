#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as websocket
import socket, time


class wsclient(tcp_handler.tcp_handler):
    __is_delete = None
    __up_time = None

    __handshake_ok = None

    __encoder = None
    __decoder = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__is_delete = False
        self.__handshake_ok = False
        self.__encoder = websocket.encoder()
        self.__decoder = websocket.decoder()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.__up_time = time.time()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.send_handshake()

    def send_handshake(self):
        pass

    def recv_handshake(self):
        pass

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.recv_handshake()
            return

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        if self.__is_delete: return
        self.__is_delete = True
        self.unregister(self.fileno)
        self.close()
