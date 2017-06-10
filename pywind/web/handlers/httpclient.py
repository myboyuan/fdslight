#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httpclient as httpclient_lib


class httpclient(tcp_handler.tcp_handler):
    __parser = None
    __builder = None

    def init_func(self, creator, host, ssl_on=False, certs=None, is_ipv6=False, callback=None):
        pass

    def connect_ok(self):
        pass

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_delete(self):
        self.delete_handler(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)
