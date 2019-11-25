#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, sys

try:
    import dns.message
except ImportError:
    print("please install dnspython3 module")
    sys.exit(-1)


class dns_proxy(udp_handler.udp_handler):
    __query_timer = None
    __dns_map = None
    __dnsserver = None

    def init_func(self, creator_fd, address, dnsserver, is_ipv6=False):
        self.__query_timer = timer.timer()
        self.__dnsserver = dnsserver

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def send_query_request(self, dns_msg):
        """发送查询请求
        :return:
        """
        pass

    def handle_from_dnsserver(self, dns_msg):
        pass

    def udp_readable(self, message, address):
        pass

    def udp_writable(self):
        pass

    def udp_timeout(self):
        pass

    def udp_error(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
