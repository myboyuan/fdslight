#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler


class tcp_proxy(tcp_handler.tcp_handler):
    pass


class udp_proxy(udp_handler.udp_handler):
    pass
