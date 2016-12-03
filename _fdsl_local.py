#!/usr/bin/env python3
import freenet.handler.dns_proxy as dns_proxy
import _fdsl


class fdslightlc(_fdsl.fdslight):
    __tun_fd = None

    __dns_fd = None
    __nameserver = None

    def __init__(self):
        super(fdslightlc, self).__init__()
        self.set_mode("local")

    def create_fn_local(self):
        pass

    def __is_ipv4_dns_request(self):
        pass

    def __is_ipv6_dns_request(self):
        pass

    def is_dns_request(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return

