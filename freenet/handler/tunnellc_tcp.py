#!/usr/bin/env python3

import pywind.evtframework.handler.tcp_handler as tcp_handler

class tunnelc_tcp(tcp_handler.tcp_handler):
    __encrypt=None
    __decrypt=None

    def init_func(self, creator, session_id,tun_fd,dns_fd, is_ipv6=False):
        pass

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "request_dns": return
        dns_msg, = args

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_timeout(self):
        pass

    def tcp_error(self):
        pass