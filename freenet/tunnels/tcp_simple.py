#!/usr/bin/env python3
import freenet.handler.tunnels_tcp_base as tunnels_base
import fdslight_etc.fn_server as fns_config


class tunnel(tunnels_base.tunnels_tcp_base):
    def fn_init(self):
        pass

    def fn_recv(self, session_id,pkt_len):
        return True

    def fn_send(self, session_id,pkt_len):
        return True

    def fn_close(self):
        pass
