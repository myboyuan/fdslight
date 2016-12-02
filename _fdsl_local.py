#!/usr/bin/env python3
import _fdsl, os, sys
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnellc_udp
import freenet.handler.tundev as tundev
import fdslight_etc.fn_local as fnlc_config
import freenet.lib.file_parser as file_parser
import socket
import pywind.lib.timer as timer
import freenet.lib.base_proto.utils as proto_utils
import freenet.handler.dns_proxy as dns_proxy


class fdslightlc(_fdsl.fdslight):
    __DEV_NAME = "fdslight"
    __tunnel_ok = False
    __tunnel_fd = None

    __tun_fd = -1
    __dns_fd = -1

    # 客户端预定义的DNS服务器
    __dns_servers = None

    __timer = None
    # 路由超时时间
    __ROUTER_TIMEOUT = 1200

    __session_id = None

    def __init__(self):
        super(fdslightlc, self).__init__()
        self.set_mode("local")
        self.__dns_servers = {}

        servers = file_parser.get_linux_host_nameservers(fnlc_config.configs["dns_resolv"])
        for ipaddr in servers:
            naddr = socket.inet_aton(ipaddr)
            self.__dns_servers[naddr] = None
        self.__dns_map = {}
        self.__timer = timer.timer()

        account = fnlc_config.configs["account"]
        username = account["username"]
        password = account["password"]

        self.__session_id = proto_utils.gen_session_id(username, password)

    def create_fn_local(self):
        self.__dns_fd = self.create_handler(-1, dns_proxy.dnslocal_proxy,
                                            self.__session_id, self.__tun_fd, fnlc_config.configs["dns"]
                                            )
        self.__tun_fd = self.create_handler(-1, tundev.tunlc, self.__DEV_NAME, self.__dns_fd)

    def set_router(self, ipaddr, prefix):
        name = "%s/%s" % (ipaddr, prefix)
        cmd = "route add -net %s/%s dev %s" % (ipaddr, prefix, self.__DEV_NAME)

        self.__timer.set_timeout(name, self.__ROUTER_TIMEOUT)
        os.system(cmd)

    def del_router(self, ipaddr, prefix):
        cmd = "route del -net %s/%s dev %s" % (ipaddr, prefix, self.__DEV_NAME)
        os.system(cmd)

    def update_router_access_time(self, ipaddr, prefix):
        """更新路由访问时间"""
        # 排除DNS服务器
        ippkt = socket.inet_aton(ipaddr)
        if ippkt in self.__dns_servers: return

        name = "%s/%s" % (ipaddr, prefix,)
        self.__timer.set_timeout(name, self.__ROUTER_TIMEOUT)

    def is_set_router(self, ipaddr, prefix):
        """检查是否设置了路由"""
        name = "%s/%s" % (ipaddr, prefix)

        return self.__timer.exists(name)

    def open_tunnel(self):
        tunnel_type = fnlc_config.configs["tunnel_type"].lower()
        args = (self.__session_id, self.__tun_fd, self.__dns_fd,)
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnellc_udp.tunnelc_udp
        else:
            tunnel = tunnellc_tcp.tunnelc_tcp

        self.__tunnel_fd = self.create_handler(-1, tunnel, *args, **kwargs)

    def tunnel_ok(self):
        self.__tunnel_ok = True

    def tunnel_fail(self):
        self.__tunnel_ok = False

    def tunnel_is_ok(self):
        return self.__tunnel_ok

    def get_tunnel(self):
        return self.__tun_fd

    def is_dns_request(self, packet):
        """是否是DNS请求"""
        protocol = packet[9]
        ihl = (packet[0] & 0x0f) * 4
        if protocol != 17: return False
        a = ihl + 2
        b = a + 1

        dport = (packet[a] << 8) | packet[b]
        if dport != 53: return False
        daddr = packet[16:20]

        return daddr in self.__dns_servers

    def get_tunnel_fileno(self):
        return self.__tunnel_fd

    def myloop(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.__timer.drop(name)
            cmd = "route del -net %s dev %s" % (name, self.__DEV_NAME)
            os.system(cmd)
        return
