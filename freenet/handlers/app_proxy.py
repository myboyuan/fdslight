#!/usr/bin/env python3


import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import freenet.lib.base_proto.app_proxy as app_proxy_proto
import time, socket


class tcp_proxy(tcp_handler.tcp_handler):
    __TIMEOUT = 600
    __update_time = 0

    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.__update_time = time.time()

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        t = time.time() - self.__update_time

        if t > self.__TIMEOUT:
            self.delete_handler(self.fileno)
        return


class udp_proxy(udp_handler.udp_handler):
    pass
