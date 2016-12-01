#!/usr/bin/env python3

import pywind.evtframework.handler.udp_handler as udp_handler


class tunnelc_udp(udp_handler.udp_handler):
    def init_func(self, creator, tun_fd, is_ipv6=False):
        pass