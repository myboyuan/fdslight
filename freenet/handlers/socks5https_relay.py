#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler

import socket, time

import freenet.lib.socks2https as socks2https


class listener(tcp_handler.tcp_handler):
    __cfg_name = None
    __is_ipv6 = None
    __conn_timeout = None

    def init_func(self, creator_fd, address, cfg_name, conn_timeout=60, is_ipv6=False):
        self.__cfg_name = cfg_name
        self.__is_ipv6 = is_ipv6
        self.__conn_timeout = conn_timeout

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

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(-1, handler, cs, caddr, self.__cfg_name, conn_timeout=self.__conn_timeout,
                                is_ipv6=self.__is_ipv6)
        ''''''


class udp_listener(udp_handler.udp_handler):
    __name = None
    __is_ipv6 = None

    def init_func(self, creator_fd, address, cfg_name, is_ipv6=False):
        self.__name = cfg_name
        self.__is_ipv6 = is_ipv6

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        pass

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        pass

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.del_relay_service(self.__name)

        self.unregister(self.fileno)
        self.close()

    def handle_udp_udplite_data(self, address, message):
        pass

    def tell_conn_ok(self):
        pass

    def tell_close(self):
        pass


class handler(tcp_handler.tcp_handler):
    __caddr = None
    __cfg_name = None
    __is_ipv6 = None
    __time = None
    __conn_timeout = None

    def init_func(self, creator_fd, cs, caddr, config_name, conn_timeout=60, is_ipv6=False):
        self.__caddr = caddr
        self.__cfg_name = config_name
        self.__is_ipv6 = is_ipv6
        self.__time = time.time()
        self.__conn_timeout = conn_timeout

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def tcp_readable(self):
        self.__time = time.time()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.dispatcher.del_relay_service(self.__cfg_name)

        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, byte_data):
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)

    def tell_conn_ok(self):
        pass

    def tell_close(self):
        self.delete_handler(self.fileno)
