#!/usr/bin/env python3

import _fdsl,sys
import freenet.handler.dns_proxy as dns_proxy
import freenet.handler.tunnels_tcp as tunnels_tcp
import freenet.handler.tunnels_udp as tunnels_udp
import fdslight_etc.fn_server as fns_config
import freenet.handler.tundev as tundev
import freenet.lib.static_nat as static_nat


class fdslightd(_fdsl.fdslight):
    def __init__(self):
        super(fdslightd, self).__init__()
        self.set_mode("server")

    def create_fn_server(self):
        name = "freenet.tunnels_auth.%s" % fns_config.configs["auth_module"]
        __import__(name)

        m = sys.modules[name]
        auth_module = m.auth()
        auth_module.init()

        if not self.debug:
            sys.stdout = open(fns_config.configs["access_log"], "a+")
            sys.stderr = open(fns_config.configs["error_log"], "a+")

        subnet = fns_config.configs["subnet"]
        nat = static_nat.nat(subnet)

        subnet = fns_config.configs["subnet"]

        tun_fd = self.create_handler(-1, tundev.tuns, "fdslight", subnet, nat)
        dns_fd = self.create_handler(-1, dns_proxy.dnsd_proxy, fns_config.configs["dns"])
        self.get_handler(dns_fd).set_dns_id_max(int(fns_config.configs["max_dns_request"]))

        args = (tun_fd, -1, dns_fd, auth_module)
        kwargs = {"debug": self.debug}

        self.create_handler(-1, tunnels_udp.tunnels_udp_listener, *args, **kwargs)
        self.create_handler(-1, tunnels_tcp.tunnel_tcp_listener, *args, **kwargs)

        if fns_config.configs["enable_ipv6_tunnel"]:
            kwargs["is_ipv6"] = True
            self.create_handler(-1, tunnels_udp.tunnels_udp_listener, *args, **kwargs)
            self.create_handler(-1, tunnels_tcp.tunnel_tcp_listener, *args, **kwargs)
        return
