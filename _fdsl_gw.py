#!/usr/bin/env python3
import _fdsl, os, sys, signal, socket
import pywind.lib.timer as timer
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.file_parser as file_parser
import freenet.handler.dns_proxy as dns_proxy
import fdslight_etc.fn_gw as fngw_config
import freenet.handler.tunnelgw_tcp as tunnelc_tcp
import freenet.handler.tunnelgw_udp as tunnelc_udp
import freenet.lib.base_proto.utils as proto_utils
import freenet.handler.tundev as tundev


class fdslightgw(_fdsl.fdslight):
    __tunnel_fd = -1
    __dns_fd = -1
    __tun_fd = -1

    __timer = None

    # 过滤器中需要删除的IP
    __routers = None
    __session_id = None

    __TUN_NAME = "fdslight"
    __ROUTER_TIMEOUT = 900

    def __init__(self):
        super(fdslightgw, self).__init__()
        self.set_mode("gateway")
        self.__timer = timer.timer()
        self.__routers = {}

        account = fngw_config.configs["account"]
        self.__session_id = proto_utils.gen_session_id(account["username"], account["password"])

    def create_fn_gw(self):
        os.chdir("driver")
        if not os.path.isfile("fdslight.ko"):
            print("you must install this software")
            sys.exit(-1)

        path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        if os.path.exists(path): os.system("rmmod fdslight")

        # 开启ip forward
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        # 禁止接收ICMP redirect 包,防止客户端机器选择最佳路由
        os.system("echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects > /dev/null")
        os.system("insmod fdslight.ko")
        os.chdir("../")

        if not self.debug:
            sys.stdout = open(fngw_config.configs["access_log"], "a+")
            sys.stderr = open(fngw_config.configs["error_log"], "a+")

        host_rules = file_parser.parse_host_file("fdslight_etc/host_rules.txt")

        self.__tun_fd = self.create_handler(-1, tundev.tungw, self.__TUN_NAME)
        self.__dns_fd = self.create_handler(-1, dns_proxy.dnsgw_proxy, self.__session_id, host_rules, debug=self.debug)
        self.get_handler(self.__dns_fd).set_dns_id_max(int(fngw_config.configs["max_dns_request"]))

        signal.signal(signal.SIGUSR1, self.__update_host_rules)

    def __update_host_rules(self, signum, frame):
        host_rules = file_parser.parse_host_file("fdslight_etc/host_rules.txt")
        self.get_handler(self.__dns_fd).update_host_rules(host_rules)

    def open_tunnel(self):
        tunnel_type = fngw_config.configs["tunnel_type"].lower()
        args = (self.__session_id, self.__dns_fd, self.raw_sock_fd, self.raw6_sock_fd)
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnelc_udp.tunnelc_udp
        else:
            tunnel = tunnelc_tcp.tunnelc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, *args, **kwargs)

    def myloop(self):
        if not self.handler_exists(self.__tunnel_fd): return

        for ip in self.__timer.get_timeout_names():
            if not self.__timer.exists(ip): continue
            self.__timer.drop(ip)
            if ip not in self.__routers: continue
            self.del_router(ip)
        return

    def update_router_access_time(self, ipaddr):
        """更新路由访问时间"""
        if ipaddr not in self.__routers: return
        self.__timer.set_timeout(ipaddr, self.__ROUTER_TIMEOUT)

    def set_router(self, ipaddr):
        if ipaddr in self.__routers: return
        cmd = "route add -host %s dev %s" % (ipaddr, self.__TUN_NAME)
        os.system(cmd)
        self.__routers[ipaddr] = None
        self.__timer.set_timeout(ipaddr, self.__ROUTER_TIMEOUT)

    def del_router(self, ipaddr):
        if ipaddr not in self.__routers: return

        cmd = "route del -host %s dev %s" % (ipaddr, self.__TUN_NAME)
        os.system(cmd)
        self.__timer.drop(ipaddr)
        del self.__routers[ipaddr]

    def get_tunnel(self):
        return self.__tunnel_fd

    def get_tun(self):
        return self.__tun_fd
