#!/usr/bin/env python3
import freenet.handler.dns_proxy as dns_proxy
import fdslight_etc.fn_local as fnlc_config
import _fdsl, os, socket, sys, signal
import freenet.handler.tundev as tundev
import pywind.lib.timer as timer
import freenet.handler.tunnellc_tcp as tunnellc_tcp
import freenet.handler.tunnellc_udp as tunnellc_udp
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.file_parser as file_parser
import dns.resolver


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
        self.__dns_fd = self.create_handler(-1, dns_proxy.dnslc_proxy, *args, debug=self.debug)
        self.__update_host_rules()

        signal.signal(signal.SIGUSR1, self.__update_host_rules)
        # 设置DNS路由
        cmd = "route add -host %s dev %s" % (fnlc_config.configs["virtual_dns"], self.__TUN_NAME)
        os.system(cmd)

    def __update_host_rules(self):
        host_rules = file_parser.parse_host_file("fdslight_etc/host_rules.txt")
        self.get_handler(self.__dns_fd).update_host_rules(host_rules)

    def __is_ipv4_dns_request(self, byte_data):
        if len(byte_data) < 28: return False
        if byte_data[9] != 17: return False

        ihl = (byte_data[0] & 0x0f) * 4
        daddr = byte_data[16:20]

        if daddr != self.__nameserver: return False
        a, b = (ihl + 2, ihl + 3)
        dport = (byte_data[a] << 8) | byte_data[b]

        return dport == 53

    def __is_ipv6_dns_request(self, byte_data):
        return False

    def is_dns_request(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return

        if ip_ver == 4: return self.__is_ipv4_dns_request(byte_data)
        return self.__is_ipv6_dns_request(byte_data)

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
        kwargs = {"is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnellc_udp.tunnellc_udp
        else:
            tunnel = tunnellc_tcp.tunnellc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, self.__session_id, **kwargs)

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
        del self.__routers[ipaddr]

    def update_router_access_time(self, ipaddr):
        """更新路由访问时间"""
        if ipaddr not in self.__routers: return
        self.set_timeout(ipaddr, self.__ROUTER_TIMEOUT)

    def get_dns(self):
        return self.__dns_fd

    def myloop(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            if name not in self.__routers: continue
            self.del_router(name)
            del self.__routers[name]
        return

    def get_tun(self):
        return self.__tun_fd

    def get_ipaddr(self, s, is_ipv6=False):
        """获取ip地址"""
        if is_ipv6:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
        is_host = False
        try:
            socket.inet_pton(family, s)
        except:
            is_host = True
        # 如果不是主机,那么就是IP地址
        if not is_host: return s
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [fnlc_config.configs["remote_dns"], ]

        addrs = []
        if is_ipv6:
            anwer = my_resolver.query(s, "aaaa")
        else:
            anwer = my_resolver.query(s, "a")
        for r in anwer: addrs.append(r.__str__())

        return addrs.pop(0)
