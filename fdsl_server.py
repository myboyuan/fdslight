#!/usr/bin/env python3
import sys, getopt, os, signal, importlib

sys.path.append("./")

PID_FILE = "/tmp/fdslight.pid"
LOG_FILE = "/tmp/fdslight.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.lib.proc as proc
import freenet.handlers.dns_proxy as dns_proxy
import freenet.handlers.tundev as tundev
import freenet.lib.fn_utils as fn_utils
import freenet.lib.utils as utils
import pywind.lib.configfile as configfile
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.nat as nat
import freenet.handlers.tunnels as tunnels
import freenet.lib.ipfrag as ipfrag
import freenet.handlers.traffic_pass as traffic_pass


class _fdslight_server(dispatcher.dispatcher):
    """网络IO进程
    """
    __configs = None
    __debug = None

    __access = None
    __mbuf = None

    __nat4 = None
    __nat6 = None

    __udp6_fileno = -1
    __tcp6_fileno = -1

    __udp_fileno = -1
    __tcp_fileno = -1

    __dns_fileno = -1

    __tcp_crypto = None
    __udp_crypto = None

    __crypto_configs = None

    __support_ip4_protocols = (1, 6, 17, 132, 136,)
    __support_ip6_protocols = (6, 7, 17, 44, 58, 132, 136,)

    __tundev_fileno = -1

    __DEVNAME = "fdslight"

    # 是否开启NAT66
    __enable_nat66 = False

    __ip4fragments = None

    __ip4_udp_proxy = None

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug

        self.__ip4fragments = {}
        self.__ip4_udp_proxy = {}

        signal.signal(signal.SIGINT, self.__exit)

        conn_config = self.__configs["connection"]
        mod_name = "freenet.access.%s" % conn_config["access_module"]

        try:
            access = importlib.import_module(mod_name)
        except ImportError:
            print("cannot found access module")
            sys.exit(-1)

        crypto_mod_name = conn_config["crypto_module"]

        tcp_crypto = "freenet.lib.crypto.%s.%s_tcp" % (crypto_mod_name, crypto_mod_name)
        udp_crypto = "freenet.lib.crypto.%s.%s_udp" % (crypto_mod_name, crypto_mod_name)

        crypto_configfile = "./fdslight_etc/%s" % conn_config["crypto_configfile"]

        try:
            self.__tcp_crypto = importlib.import_module(tcp_crypto)
            self.__udp_crypto = importlib.import_module(udp_crypto)
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        if not os.path.isfile(crypto_configfile):
            print("cannot found crypto configfile")
            sys.exit(-1)

        try:
            self.__crypto_configs = proto_utils.load_crypto_configfile(crypto_configfile)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        enable_ipv6 = bool(int(conn_config["enable_ipv6"]))

        tcp_port = int(conn_config["listen_tcp_port"])
        udp_port = int(conn_config["listen_udp_port"])

        conn_timeout = int(conn_config["conn_timeout"])

        listen_ip = conn_config["listen_ip"]
        listen_ip6 = conn_config["listen_ip6"]

        listen_tcp = (listen_ip, tcp_port,)
        listen_udp = (listen_ip, udp_port,)

        listen6_tcp = (listen_ip6, tcp_port,)
        listen6_udp = (listen_ip6, udp_port,)

        if enable_ipv6:
            self.__tcp6_fileno = self.create_handler(
                -1, tunnels.tcp_handler,
                listen6_tcp, self.__tcp_crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=True
            )
            self.__udp6_fileno = self.create_handler(
                -1, tunnels.udp_handler,
                listen6_udp, self.__udp_crypto, self.__crypto_configs, is_ipv6=True
            )

        self.__tcp_fileno = self.create_handler(
            -1, tunnels.tcp_tunnel,
            listen_tcp, self.__tcp_crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=False
        )
        self.__udp_fileno = self.create_handler(
            -1, tunnels.udp_tunnel,
            listen_udp, self.__udp_crypto, self.__crypto_configs, is_ipv6=False
        )

        self.__tundev_fileno = self.create_handler(
            -1, tundev.tundevs, self.__DEVNAME
        )

        self.__access = access.access(self)

        self.__mbuf = fn_utils.mbuf()

        nat_config = configs["nat"]

        dns_addr = nat_config["dns"]
        if utils.is_ipv6_address(dns_addr):
            is_ipv6 = True
        else:
            is_ipv6 = False

        self.__dns_fileno = self.create_handler(
            -1, dns_proxy.dnsd_proxy, dns_addr, is_ipv6=is_ipv6
        )

        enable_ipv6 = bool(int(nat_config["enable_nat66"]))
        ip6addr = nat_config["local_ip6"]
        eth_name = nat_config["eth_name"]

        if enable_ipv6:
            self.__nat6 = nat.nat66(ip6addr)
            self.__enable_nat66 = True
            self.__config_gateway6(ip6addr)

        subnet, prefix = utils.extract_subnet_info(nat_config["virtual_ip_subnet"])
        self.__nat4 = nat.nat((subnet, prefix,))
        self.__config_gateway(subnet, prefix, eth_name)

    def myloop(self):
        if self.__enable_nat66: self.__nat6.recycle()
        self.__nat4.recycle()
        self.__access.access_loop()
        return

    def handle_msg_from_tunnel(self, fileno, session_id, address, action, message):
        if action == proto_utils.ACT_DATA:
            self.__mbuf.copy2buf(message)
            size = self.__mbuf.payload_size
        else:
            size = len(message)

        b = self.__access.data_from_recv(fileno, session_id, address, size)
        if not b: return False
        if action == proto_utils.ACT_DNS:
            self.__request_dns(session_id, message)
            return True

        return self.__handle_ipdata_from_tunnel(session_id)

    def __handle_ipdata_from_tunnel(self, session_id):
        ip_ver = self.__mbuf.ip_version()

        if ip_ver not in (4, 6,): return False
        if ip_ver == 4: return self.__handle_ipv4data_from_tunnel(session_id)

        return self.__handle_ipv6data_from_tunnel(session_id)

    def __handle_ipv6data_from_tunnel(self, session_id):
        return True

    def __handle_ipv4data_from_tunnel(self, session_id):
        self.__mbuf.offset = 9
        protocol = self.__mbuf.get_part(1)

        # MTU 最大为1500
        if self.__mbuf.payload_size > 1500: return False
        if self.__get_ip4_hdrlen() + 8 > self.__mbuf.payload_size: return False

        if protocol not in self.__support_ip4_protocols: return False

        # 对UDP和UDPLite进行特殊处理,以支持内网穿透
        if protocol == 17 or protocol == 136:
            is_udplite = False
            if protocol == 136: is_udplite = True
            self.__handle_ipv4_dgram_from_tunnel(session_id, is_udplite=is_udplite)
            return True
        self.__mbuf.offset = 0
        ip4data = self.__mbuf.get_data()

        rs = self.__nat4.get_ippkt2sLan_from_cLan(session_id, ip4data)
        if not rs: return
        self.get_handler(self.__tundev_fileno).handle_msg_from_tunnel(rs)
        return True

    def __send_msg_to_tunnel(self, session_id, action, message):
        if not self.__access.session_exists(session_id): return
        if not self.__access.data_for_send(session_id, self.__mbuf.payload_size): return

        session_info = self.__access.get_session_info(session_id)
        fileno = session_info[0]

        self.get_handler(fileno).send_msg(session_id, session_info[2], action, message)

    def send_msg_to_tunnel_from_tun(self, message):
        self.__mbuf.copy2buf(message)

        ip_ver = self.__mbuf.ip_version()

        if ip_ver == 4:
            rs = self.__nat4.get_ippkt2cLan_from_sLan(message)
        else:
            rs = self.__nat6.get_nat_reverse(self.__mbuf)

        if not rs: return

        self.__mbuf.offset = 0
        session_id, pkt = rs
        self.__send_msg_to_tunnel(session_id, proto_utils.ACT_DATA, pkt)

    def send_msg_to_tunnel_from_p2p_proxy(self, session_id, message):
        self.__send_msg_to_tunnel(session_id, proto_utils.ACT_DATA, message)

    def response_dns(self, session_id, message):
        if not self.__access.session_exists(session_id): return

        fileno, _, address, _ = self.__access.get_session_info(session_id)
        if not self.handler_exists(fileno): return

        self.get_handler(fileno).send_msg(session_id, address, proto_utils.ACT_DNS, message)

    def __send_msg(self, session_id, action, message):
        pass

    def __request_dns(self, session_id, message):
        self.get_handler(self.__dns_fileno).request_dns(session_id, message)

    def __config_gateway(self, subnet, prefix, eth_name):
        """ 配置IPV4网关
        :param subnet:子网
        :param prefix:子网前缀
        :param eth_name:流量出口网卡名
        :return:
        """
        # 添加一条到tun设备的IPV4路由
        cmd = "route add -net %s/%s dev %s" % (subnet, prefix, self.__DEVNAME)
        os.system(cmd)
        # 开启ip forward
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        # 开启IPV4 NAT
        os.system("iptables -t nat -A POSTROUTING -s %s/%s -o %s -j MASQUERADE" % (subnet, prefix, eth_name,))
        os.system("iptables -A FORWARD -s %s/%s -j ACCEPT" % (subnet, prefix))

    def __config_gateway6(self, ip6address):
        """配置IPV6网关
        :param ip6address:
        :param eth_name:
        :return:
        """
        # 添加一条到tun设备的IPv6路由
        cmd = "route add -A inet6 -host %s dev %s" % (ip6address, self.__DEVNAME)
        os.system(cmd)
        # 开启IPV6流量重定向
        os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")

    def __get_ip4_hdrlen(self):
        self.__mbuf.offset = 0
        n = self.__mbuf.get_part(0)
        hdrlen = (n & 0x0f) * 4
        return hdrlen

    def __handle_ipv4_dgram_from_tunnel(self, session_id, is_udplite=False):
        """处理IPV4数据报
        :return:
        """
        ipfragment = self.__ip4fragments[session_id]
        ipfragment.add_frag(self.__mbuf)

        data = ipfragment.get_data()
        if not data: return

        saddr, daddr, sport, dport, msg = data
        if session_id not in self.__ip4_udp_proxy:
            self.__ip4_udp_proxy[session_id] = {}
        pydict = self.__ip4_udp_proxy[session_id]

        udp_id = "%s-%s" % (saddr, sport,)
        if udp_id not in pydict:
            fileno = self.create_handler(
                -1, traffic_pass.p2p_proxy,
                session_id, (saddr, sport), is_udplite=is_udplite
            )
            pydict[udp_id] = fileno
        fileno = pydict[udp_id]
        self.get_handler(fileno).send_msg(msg, (daddr, dport))

    def tell_register_session(self, session_id):
        """告知注册session
        :param session_id:
        :return:
        """
        self.__ip4fragments[session_id] = ipfrag.ip4_p2p_proxy()

    def tell_unregister_session(self, session_id):
        """告知取消session注册
        :param session_id:
        :return:
        """
        del self.__ip4fragments[session_id]

    def tell_del_udp_proxy(self, session_id, saddr, sport):
        """告知删除UDP代理
        :param session_id:
        :param saddr:
        :param sport:
        :return:
        """
        if session_id not in self.__ip4_udp_proxy: return
        pydict = self.__ip4_udp_proxy[session_id]
        key = "%s-%s" % (saddr, sport)

        if key not in pydict: return
        del pydict[key]
        if not pydict: del self.__ip4_udp_proxy[session_id]

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)
        sys.exit(-1)

def __start_service(debug):
    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

    configs = configfile.ini_parse_from_file("fdslight_etc/fn_server.ini")
    cls = _fdslight_server()
    cls.ioloop(debug, configs)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found fdslight server process")
        return

    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""

    for k, v in opts:
        if k == "-d": d = v
    if not d:
        print(help_doc)
        return

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    debug = False

    if d == "stop":
        __stop_service()
        return
    if d == "debug": debug = True
    if d == "start": debug = True

    __start_service(debug)


if __name__ == '__main__': main()
