#!/usr/bin/env python3

import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.dhcp.lib.dhcp as dhcp


class _dhcp_base(udp_handler.udp_handler):
    configs = None

    def init_func(self, creator, configs):
        self.configs = configs

    def udp_readable(self, message, address):
        pass


class dhcpd(_dhcp_base):
    pass


class dhcpc(udp_handler.udp_handler):
    pass
