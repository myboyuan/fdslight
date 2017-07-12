#!/usr/bin/env python3
"""HTTP socks5代理
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler


class http_socks5_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, address, is_ipv6=False):
        pass

    def tcp_readable(self):
        pass

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _http_socks5_handler(tcp_handler.tcp_handler):
    def init_func(self, creator, cs, caddr):
        pass


class _tcp_client(tcp_handler.tcp_handler):
    pass


class _udp_handler(udp_handler.udp_handler):
    pass
