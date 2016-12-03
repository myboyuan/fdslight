#!/usr/bin/env python3
import freenet.handler.dns_proxy as dns_proxy
import fdslight_etc.fn_local as fnlc_config
import _fdsl, os, socket
import freenet.handler.tundev as tundev
import pywind.lib.timer as timer
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnellc_udp


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

    def __init__(self):
        super(fdslightlc, self).__init__()
        self.set_mode("local")
        self.__timer = timer.timer()
        self.__routers = {}

    def create_fn_local(self):
        self.__tun_fd = self.create_handler(-1, tundev.tunlc, self.__TUN_NAME)

        if fnlc_config.configs["virtual_dns"] == fnlc_config.configs["remote_dns"]:
            raise ValueError("virtual_dns and remote_dns are same")

        args = (
            self.__tun_fd,
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
        args = (self.__session_id, self.__dns_fd, self.raw_sock_fd, self.raw6_sock_fd)
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnellc_udp.tunnellc_udp
        else:
            tunnel = tunnellc_tcp.tunnellc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, *args, **kwargs)

    def set_router(self, ipaddr, prefix):
        cmd = "route add -net %s/%s dev %s" % (ipaddr, prefix, self.__TUN_NAME)
        os.system(cmd)

    def del_router(self, ipaddr, prefix):
        cmd = "route del -net %s/%s dev %s" % (ipaddr, prefix, self.__TUN_NAME)
        os.system(cmd)

    def update_router_access_time(self, ipaddr, prefix):
        """更新路由访问时间"""
        pass

    def get_dns(self):
        return self.__dns_fd

    def myloop(self):
        pass
