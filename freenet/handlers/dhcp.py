#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler


class dhcpd(udp_handler.udp_handler):
    def init_func(self, creator, bind_ip, dnsserver, gateway):
        pass

    def set_mac_ip_relative(self, mac, ip):
        """设定MAC与IP相互关联
        :param mac:
        :param ip:
        :return:
        """
        pass
