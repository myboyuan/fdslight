#!/usr/bin/env python3
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket, time, os
import freenet.lib.logging as logging


class listener(tcp_handler.tcp_handler):
    __is_ipv6 = None
    __remote_info = None
    __auth_id = None

    def init_func(self, creator_fd, address, auth_id, remote_info, is_ipv6=False):
        self.__is_ipv6 = is_ipv6
        self.__remote_info = remote_info
        self.__auth_id = auth_id

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr, self.__auth_id, is_ipv6=self.__is_ipv6)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    __remote_info = None
    __caddr = None
    __auth_id = None
    __time = None

    __timeout = None

    def init_func(self, creator_fd, cs, caddr, auth_id, remote_info):
        self.__caddr = caddr
        self.__remote_info = remote_info
        self.__auth_id = auth_id
        self.__time = time.time()
        self.__timeout = remote_info["timeout"]

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def tcp_readable(self):
        self.__time = time.time()
        rdata = self.reader.read()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__timeout > self.__timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
