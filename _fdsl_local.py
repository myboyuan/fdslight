#!/usr/bin/env python3
import _fdsl, os
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnellc_udp
import freenet.handler.tundev as tundev
import fdslight_etc.fn_local as fnlc_config
import freenet.lib.file_parser as file_parser
import socket


class fdslightlc(_fdsl.fdslight):
    __DEV_NAME = "fdslight"
    __tunnel_ok = False
    __tunnel_fd = None
    __tun_fd = -1

    # 客户端预定义的DNS服务器
    __dns_servers = None

    def __init__(self):
        super(fdslightlc, self).__init__()
        self.set_mode("local")
        self.__dns_servers = {}

        servers = file_parser.get_linux_host_nameservers(fnlc_config.configs["dns_resolv"])
        for ipaddr in servers:
            naddr = socket.inet_aton(ipaddr)
            self.__dns_servers[naddr] = None
        self.__dns_map={}
        return

    def create_fn_local(self):
        self.__tun_fd = self.create_handler(-1, tundev.tunlc, self.__DEV_NAME)

    def myloop(self):
        pass

    def set_router(self, ipaddr, prefix):
        cmd = "route add -net %s/%s dev %s" % (ipaddr, prefix, self.__DEV_NAME)
        os.system(cmd)

    def del_router(self, ipaddr, prefix):
        cmd = "route del -net %s/%s dev %s" % (ipaddr, prefix, self.__DEV_NAME)
        os.system(cmd)

    def open_tunnel(self):
        tunnel_type = fnlc_config.configs["tunnel_type"].lower()
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnellc_udp.tunnelc_udp
        else:
            tunnel = tunnellc_tcp.tunnelc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, self.__tun_fd, is_ipv6=False)

    def tunnel_ok(self):
        self.__tunnel_ok = True

    def tunnel_fail(self):
        self.__tunnel_ok = False

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
