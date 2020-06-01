#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler


class fwd(udp_handler.udp_handler):
    def init_func(self, creator_fd, *args, **kwargs):
        pass
