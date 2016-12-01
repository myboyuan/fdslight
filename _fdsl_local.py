#!/usr/bin/env python3
import _fdsl, os
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnel_udp
import fdslight_etc.fn_local as fnlc_config


class fdslightlc(_fdsl.fdslight):
    def create_fn_local(self):
        pass

    def myloop(self):
        pass

    def set_router(self, ipaddr, prefix):
        pass
