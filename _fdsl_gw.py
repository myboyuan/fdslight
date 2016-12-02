#!/usr/bin/env python3
import _fdsl, os, sys, signal, socket
import pywind.lib.timer as timer
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.file_parser as file_parser
import freenet.handler.dns_proxy as dns_proxy
import fdslight_etc.fn_gw as fngw_config
import freenet.handler.tunnelgw_tcp as tunnelc_tcp
import freenet.handler.tunnelgw_udp as tunnelc_udp
import freenet.lib.whitelist as whitelist
import freenet.lib.base_proto.utils as proto_utils


class fdslightgw(_fdsl.fdslight):
    __tunnel_fd = -1
    __filter_fd = None
    __dns_fd = -1

    __whitelist = None

    __udp_no_proxy_clients = None
    __udp_global_proxy_clients = None

    __timer = None

    # 过滤器中需要删除的IP
    __wait_del_ips_from_filter = None
    # 过滤器IP保存时间
    __FILTER_IP_LIFETIME = 1200

    __session_id = None

    def __init__(self):
        super(fdslightgw, self).__init__()
        self.set_mode("gateway")
        self.__timer = timer.timer()
        self.__wait_del_ips_from_filter = []
        self.__udp_no_proxy_clients = {}
        self.__udp_global_proxy_clients = {}

        account = fngw_config.configs["account"]
        self.__session_id = proto_utils.gen_session_id(account["username"], account["password"])

        udp_no_proxy_clients = fngw_config.configs["udp_no_proxy_clients"]
        udp_global_proxy_clients = fngw_config.configs["udp_global_proxy_clients"]

        for ipaddr in udp_no_proxy_clients:
            naddr = socket.inet_aton(ipaddr)
            self.__udp_no_proxy_clients[naddr] = None

        for ipaddr in udp_global_proxy_clients:
            naddr = socket.inet_aton(ipaddr)
            self.__udp_global_proxy_clients[naddr] = None

    def create_fn_gw(self):
        if not self.debug: _fdsl.create_pid_file(_fdsl.FDSL_PID_FILE, os.getpid())

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

        whitelist_rules = file_parser.parse_ip_subnet_file("fdslight_etc/whitelist.txt")
        self.__whitelist = whitelist.whitelist()
        for rule in whitelist_rules: self.__whitelist.add_rule(*rule)

        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")

        self.__dns_fd = self.create_handler(-1, dns_proxy.dnsgw_proxy, self.__session_id, blacklist, debug=self.debug)

        signal.signal(signal.SIGUSR1, self.__update_blacklist)

    def __update_blacklist(self, signum, frame):
        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")
        self.get_handler(self.__dns_fd).update_blacklist(blacklist)

    def open_tunnel(self):
        tunnel_type = fngw_config.configs["tunnel_type"].lower()
        args = (self.__session_id,self.__dns_fd, self.raw_sock_fd, self.raw6_sock_fd)
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnelc_udp.tunnelc_udp
        else:
            tunnel = tunnelc_tcp.tunnelc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, *args, **kwargs)

    def is_need_send_udp_to_tunnel(self, sippkt, dippkt):
        """是否需要发送UDP流量到隧道
        :param sippkt 源地址主机网络序地址
        :param dippkt 目的地址主机网络序地址
        """
        is_global = fngw_config.configs["udp_global"]

        if is_global: return True
        print("--------")
        if sippkt in self.__udp_global_proxy_clients: return True
        if sippkt in self.__udp_no_proxy_clients: return False

        return self.__whitelist.find(dippkt)

    def set_filter_fd(self, fileno):
        self.__filter_fd = fileno

    def update_filter_ip_access_time(self, n):
        """更新过滤器IP访问时间"""
        self.__timer.set_timeout(n, self.__FILTER_IP_LIFETIME)

    def myloop(self):
        if not self.handler_exists(self.__tunnel_fd): return

        for ip in self.__timer.get_timeout_names():
            if not self.__timer.exists(ip): continue
            self.__timer.drop(ip)
            self.__wait_del_ips_from_filter.append(ip)
        while 1:
            try:
                ip = self.__wait_del_ips_from_filter.pop(0)
            except IndexError:
                break
            fdsl_ctl.tf_record_del(self.__filter_fd, ip)
        self.__whitelist.recycle_cache()
        return