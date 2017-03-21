#!/usr/bin/env python3
import sys, getopt, os, signal, importlib

sys.path.append("./")

PID_FILE = "/tmp/fdslight.pid"
LOG_FILE = "/tmp/fdslight.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.lib.proc as proc
import freenet.handlers.dns_proxy as dns_proxy
import freenet.handlers.tundev as tundev
import freenet.lib.nat as nat
import freenet.lib.fn_utils as fn_utils
import freenet.lib.utils as utils
import pywind.lib.configfile as configfile
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.nat as nat
import freenet.handlers.tunnels as tunnels


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

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug

        conn_config = self.__configs["connection"]
        mod_name = "freenet.access.%s" % conn_config["access_module"]

        try:
            access = importlib.import_module(mod_name)
        except ImportError:
            print("cannot found access module")
            sys.exit(-1)

        crypto_mod_name = conn_config["crypto_module"]

        tcp_crypto = "freenet.crypto.%s.%s_tcp" % (crypto_mod_name, crypto_mod_name)
        udp_crypto = "freenet.crypto.%s.%s_udp" % (crypto_mod_name, crypto_mod_name)

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
                listen6_udp, self.__udp_crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=True
            )

        self.__tcp_fileno = self.create_handler(
            -1, tunnels.tcp_handler,
            listen_tcp, self.__tcp_crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=False
        )
        self.__udp_fileno = self.create_handler(
            -1, tunnels.udp_handler,
            listen_udp, self.__udp_crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=False
        )

        self.__tundev_fileno = tundev.tundevs(self.__DEVNAME)

        self.__access = access.access()
        self.__access.init()

        self.__mbuf = fn_utils.mbuf()

        nat_config = configs["nat"]

        enable_ipv6 = bool(int(nat_config["enable_ipv6"]))

        if enable_ipv6:
            self.__nat6 = nat.nat66()
            self.__enable_nat66 = True
        self.__nat4 = nat.nat()

    def myloop(self):
        if self.__enable_nat66: self.__nat6.recycle()
        self.__nat4.recycle()
        self.__access.access_loop()

    def handle_msg_from_tunnel(self, fileno, session_id, action, message, address):
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
        if self.__mbuf.payload_size < 21: return False

        if protocol not in (1, 6, 17, 132, 136,): return False

        # 对UDP和UDPLite进行特殊处理,以支持内网穿透
        if protocol == 17 or protocol == 136:
            return True

        self.get_handler(self.__tundev_fileno).handle_msg_from_tunnel(self.__mbuf.get_data())

    def handle_msg_from_tun(self, message):
        pass

    def response_dns(self, session_id, message):
        pass

    def __request_dns(self, session_id, message):
        pass


def __start_service(debug):
    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

    configs = configfile.ini_parse_from_file("fdslight_etc/fn_server.ini")
    cls = _fdslight_server(debug, configs)
    cls.ioloop()


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found fdslight server process")
        return

    os.kill(pid, signal.SIGINT)


def main(): pass


if __name__ == '__main__': main()
