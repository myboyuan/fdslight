#!/usr/bin/env python3

import pywind.evtframework.handler.udp_handler as udp_handler


class tunnelc_udp(udp_handler.udp_handler):
    __encrypt = None
    __decrypt = None

    def init_func(self, creator, session_id,tun_fd,dns_fd, is_ipv6=False):
        pass

    def udp_readable(self, message, address):
        pass

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        pass

    def udp_error(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "request_dns": return
        dns_msg, = args
