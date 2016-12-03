#!/usr/bin/env python3
import freenet.handler.dns_proxy as dns_proxy
import fdslight_etc.fn_local as fnlc_config
import _fdsl, os, socket, sys
import freenet.handler.tundev as tundev
import pywind.lib.timer as timer
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnellc_udp
import freenet.lib.base_proto.utils as proto_utils


class fdslightlc(_fdsl.fdslight):
    __tun_fd = None

    __dns_fd = None
    __nameserver = None

    # 隧道是否打开
    __tunnel_ok = False

    __tunnel_fd = -1

    # 路由超时时间
    __ROUTER_TIMEOUT = 900

    __timer = None

    __TUN_NAME = "fdslight"

    __routers = None

    __session_id = None

    def __init__(self):
        super(fdslightlc, self).__init__()
        self.set_mode("local")
        self.__timer = timer.timer()
        self.__routers = {}

    def create_fn_local(self):
        if not self.debug:
            sys.stdout = open(fnlc_config.configs["access_log"], "a+")
            sys.stderr = open(fnlc_config.configs["error_log"], "a+")
        account = fnlc_config.configs["account"]
        self.__session_id = proto_utils.gen_session_id(account["username"], account["password"])

        self.__tun_fd = self.create_handler(-1, tundev.tunlc, self.__TUN_NAME)

        if fnlc_config.configs["virtual_dns"] == fnlc_config.configs["remote_dns"]:
            raise ValueError("virtual_dns and remote_dns are same")

        args = (
            fnlc_config.configs["virtual_dns"],
            fnlc_config.configs["remote_dns"]
        )

        self.__nameserver = socket.inet_aton(fnlc_config.configs["virtual_dns"])
        self.__dns_fd = self.create_handler(-1, dns_proxy.dnslc_proxy, *args)

    def __is_ipv4_dns_request(self, byte_data):
        if len(byte_data) < 28: return

        ihl = (byte_data[0] & 0x0f) * 4
        daddr = byte_data[16:20]
        if daddr != self.__nameserver: return False
        a, b = (ihl + 2, ihl + 3)
        dport = (a << 8) | b

        return dport == 53

    def __is_ipv6_dns_request(self):
        return False

    def is_dns_request(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return

        if ip_ver == 4: return self.__is_ipv4_dns_request()
        return self.__is_ipv6_dns_request()

    def tunnel_is_ok(self):
        return self.__tunnel_ok

    def tunnel_fail(self):
        self.__tunnel_ok = False

    def tunnel_ok(self):
        self.__tunnel_ok = True

    def set_tunnel_fileno(self, fileno):
        self.__tunnel_fd = fileno

    def get_tunnel(self):
        return self.__tunnel_fd

    def open_tunnel(self):
        tunnel_type = fnlc_config.configs["tunnel_type"].lower()
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnellc_udp.tunnellc_udp
        else:
            tunnel = tunnellc_tcp.tunnellc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, self.__session_id, **kwargs)

    def set_router(self, ipaddr, prefix):
        name = "%s/%s" % (ipaddr, prefix,)
        if name in self.__routers: return
        cmd = "route add -net %s/%s dev %s" % (ipaddr, prefix, self.__TUN_NAME)
        os.system(cmd)
        self.__routers[name] = (ipaddr, prefix,)
        self.__timer.set_timeout(name, self.__ROUTER_TIMEOUT)

    def del_router(self, ipaddr, prefix):
        name = "%s/%s" % (ipaddr, prefix,)
        if name not in self.__routers: return

        cmd = "route del -net %s/%s dev %s" % (ipaddr, prefix, self.__TUN_NAME)
        os.system(cmd)
        del self.__routers[name]

    def update_router_access_time(self, ipaddr, prefix):
        """更新路由访问时间"""
        name = "%s/%s" % (ipaddr, prefix,)
        if name not in self.__routers: return
        self.set_timeout(name, self.__ROUTER_TIMEOUT)

    def get_dns(self):
        return self.__dns_fd

    def myloop(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            if not self.__routers: continue
            ipaddr, prefix = self.__routers[name]
            self.del_router(ipaddr, prefix)
        return

    def get_tun(self):
        return self.__tun_fd
