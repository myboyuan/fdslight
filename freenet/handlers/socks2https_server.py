#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket,time

class listener(tcp_handler.tcp_handler):
    def init_func(self, creator_fd, address, is_ipv6=False):
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


class handler_for_tcp(tcp_handler.tcp_handler):
    def init_func(self, creator_fd, *args, **kwargs):
        pass


class handler_for_udp(udp_handler.udp_handler):
    def init_func(self, creator_fd, address, is_udplite=False, is_ipv6=False):
        pass

