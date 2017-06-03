#!/usr/bin/env python3
"""socks5本地服务端实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket


class sserverd(tcp_handler.tcp_handler):
    def init_func(self, creator, listen, listen_ipv6=False):
        if listen_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        s = socket.socket(af, socket.SOCK_STREAM)

        if listen_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(
                    self.fileno, _sserverd_handler,
                    cs, address
                )
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _sserverd_handler(tcp_handler.tcp_handler):
    def init_func(self, creator, caddr):
        pass

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        pass
