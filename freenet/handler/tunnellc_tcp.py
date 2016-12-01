#!/usr/bin/env python3

import pywind.evtframework.handler.tcp_handler as tcp_handler


class tunnelc_tcp(tcp_handler.tcp_handler):
    def init_func(self, creator, tun_fd, is_ipv6=False):
        pass

