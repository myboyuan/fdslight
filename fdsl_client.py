#!/usr/bin/env python3

import sys

sys.path.append("./")

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.timer as timer
import pywind.lib.configfile as configfile
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.proc as proc
import freenet.handlers.tundev as tundev
import os, getopt, signal, importlib, socket
import freenet.handlers.dns_proxy as dns_proxy
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.handlers.tunnelc as tunnelc
import freenet.lib.file_parser as file_parser
import dns.resolver

_MODE_GW = 1
_MODE_LOCAL = 2

PID_FILE = "/tmp/fdslight.pid"
STDERR_FILE = "/tmp/fdslight.log"
STDOUT_FILE = "/tmp/fdslight.log"


class _fdslight_client(dispatcher.dispatcher):
    # 路由超时时间
    __ROUTER_TIMEOUT = 800

    __routers = None

    __router_timer = None

    __DEVNAME = "fdslight"

    __configs = None

    __mode = 0

    __mbuf = None

    __tunnel_fileno = -1

    __dns_fileno = -1
    __tundev_fileno = -1

    __session_id = None

    __debug = False

    __tcp_crypto = None
    __udp_crypto = None
    __crypto_configs = None

    __support_ip4_protocols = (1, 6, 17, 132, 136,)
    __support_ip6_protocols = (6, 7, 17, 44, 58, 132, 136,)

    __dgram_fetch_fileno = -1

    def init_func(self, mode, debug, configs):
        self.create_poll()

        signal.signal(signal.SIGINT, self.__exit)

        self.__router_timer = timer.timer()
        self.__routers = {}
        self.__configs = configs

        if mode == "local":
            self.__mode = _MODE_LOCAL
        else:
            self.__mode = _MODE_GW

        self.__mbuf = utils.mbuf()
        self.__debug = debug

        self.__tundev_fileno = self.create_handler(
            -1, tundev.tundevc, self.__DEVNAME
        )

        public = configs["public"]
        gateway = configs["gateway"]

        is_ipv6 = utils.is_ipv6_address(public["remote_dns"])

        if self.__mode == _MODE_GW:
            self.__dns_fileno = self.create_handler(
                -1, dns_proxy.dnsc_proxy,
                gateway["dnsserver_bind"], debug=debug, server_side=True
            )
            self.get_handler(self.__dns_fileno).set_parent_dnsserver(public["remote_dns"], is_ipv6=is_ipv6)
        else:
            self.__dns_fileno = self.create_handler(
                -1, dns_proxy.dnsc_proxy,
                public["remote_dns"], debug=debug, server_side=False
            )

        self.__set_host_rules(None, None)

        if self.__mode == _MODE_GW:
            self.__load_kernel_mod()
        else:
            local = configs["local"]
            vir_dns = local["virtual_dns"]
            is_ipv6 = utils.is_ipv6_address(vir_dns)
            self.set_router(vir_dns, is_ipv6=is_ipv6, is_dynamic=False)

        conn = configs["connection"]

        m = "freenet.lib.crypto.%s" % conn["crypto_module"]
        try:
            self.__tcp_crypto = importlib.import_module("%s.%s_tcp" % (m, conn["crypto_module"]))
            self.__udp_crypto = importlib.import_module("%s.%s_udp" % (m, conn["crypto_module"]))
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        crypto_fpath = "./fdslight_etc/%s" % conn["crypto_configfile"]

        if not os.path.isfile(crypto_fpath):
            print("crypto configfile not exists")
            sys.exit(-1)

        try:
            crypto_configs = proto_utils.load_crypto_configfile(crypto_fpath)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        self.__crypto_configs = crypto_configs

        if not debug:
            sys.stderr = open(STDERR_FILE, "a+")
            sys.stdout = open(STDOUT_FILE, "a+")

    def __load_kernel_mod(self):
        os.chdir("driver")
        if not os.path.isfile("fdslight_dgram.ko"):
            print("you must install this software")
            sys.exit(-1)

        fpath = "fdslight_etc/kern_version"
        if not os.path.isfile(fpath):
            print("you must install this software")
            sys.exit(-1)

        with open(fpath, "r") as f:
            cp_ver = f.read()
            fp = os.popen("uname -r")
            now_ver = fp.read()
            fp.close()

        if cp_ver != now_ver:
            print("the kernel is changed,please reinstall this software")
            sys.exit(-1)

        path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        if os.path.exists(path): os.system("rmmod fdslight_dgram")

        # 开启ip forward
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        # 禁止接收ICMP redirect 包,防止客户端机器选择最佳路由
        os.system("echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects > /dev/null")
        os.system("insmod fdslight_dgram.ko")
        os.chdir("../")

    def handle_msg_from_tun(self, message):
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()

        if ip_ver not in (4, 6,): return

        action = proto_utils.ACT_DATA

        if ip_ver == 4:
            self.__mbuf.offset = 9
            nexthdr = self.__mbuf.get_part(1)
            self.__mbuf.offset = 16
            byte_daddr = self.__mbuf.get_part(4)
            fa = socket.AF_INET
        else:
            self.__mbuf.offset = 6
            nexthdr = self.__mbuf.get_part(1)
            self.__mbuf.offset = 24
            byte_daddr = self.__mbuf.get_part(16)
            fa = socket.AF_INET6

        sts_daddr = socket.inet_ntop(fa, byte_daddr)

        # 丢弃不支持的传输层包
        if ip_ver == 4 and nexthdr not in self.__support_ip4_protocols: return
        if ip_ver == 6 and nexthdr not in self.__support_ip6_protocols: return

        if self.__mode == _MODE_LOCAL:
            is_dns_req, saddr, daddr, sport, rs = self.__is_dns_request()
            if is_dns_req:
                self.get_handler(self.__dns_fileno).dnsmsg_from_tun(saddr, daddr, sport, rs)
                return

        self.__update_router_access(sts_daddr)
        self.send_msg_to_tunnel(action, message)

    def handle_msg_from_tunnel(self, seession_id, action, message):
        if seession_id != self.session_id: return
        if action not in proto_utils.ACTS: return

        if action == proto_utils.ACT_DNS:
            self.get_handler(self.__dns_fileno).msg_from_tunnel(message)
            return

        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        if ip_ver == 4:
            self.__mbuf.offset = 12
            byte_saddr = self.__mbuf.get_part(4)
            fa = socket.AF_INET
        else:
            self.__mbuf.offset = 8
            byte_saddr = self.__mbuf.get_part(16)
            fa = socket.AF_INET6

        host = socket.inet_ntop(fa, byte_saddr)

        self.__update_router_access(host)

        self.send_msg_to_tun(message)

    def send_msg_to_tunnel(self, action, message):
        if not self.handler_exists(self.__tunnel_fileno):
            self.__open_tunnel()

        handler = self.get_handler(self.__tunnel_fileno)
        handler.send_msg_to_tunnel(self.session_id, action, message)

    def send_msg_to_tun(self, message):
        self.get_handler(self.__tundev_fileno).msg_from_tunnel(message)

    def __is_dns_request(self):
        mbuf = self.__mbuf
        ip_ver = mbuf.ip_version()

        if ip_ver == 4:
            mbuf.offset = 0
            n = mbuf.get_part(1)
            hdrlen = (n & 0x0f) * 4

            mbuf.offset = 9
            nexthdr = mbuf.get_part(1)

            mbuf.offset = 12
            saddr = mbuf.get_part(4)
            mbuf.offset = 16
            daddr = mbuf.get_part(4)
        else:
            mbuf.offset = 6
            nexthdr = mbuf.get_part(1)
            hdrlen = 40
            mbuf.offset = 8
            saddr = mbuf.get_part(16)
            mbuf.offset = 24
            daddr = mbuf.get_part(16)

        if (nexthdr != 17): return (False, None, None, None, None)

        mbuf.offset = hdrlen
        sport = utils.bytes2number(mbuf.get_part(2))

        mbuf.offset = hdrlen + 2
        dport = utils.bytes2number(mbuf.get_part(2))
        if dport != 53: return (False, None, None, None, None,)

        mbuf.offset = hdrlen + 8

        return (True, saddr, daddr, sport, mbuf.get_data(),)

    @property
    def session_id(self):
        if not self.__session_id:
            connection = self.__configs["connection"]
            username = connection["username"]
            passwd = connection["password"]

            self.__session_id = proto_utils.gen_session_id(username, passwd)

        return self.__session_id

    def __set_host_rules(self, signum, frame):
        fpath = "fdslight_etc/host_rules.txt"

        if not os.path.isfile(fpath):
            print("cannot found host_rules.txt")
            self.__exit(signum, frame)

        rules = file_parser.parse_host_file(fpath)
        self.get_handler(self.__dns_fileno).set_host_rules(rules)

    def __open_tunnel(self):
        conn = self.__configs["connection"]
        host = conn["host"]
        port = int(conn["port"])
        enable_ipv6 = bool(int(conn["enable_ipv6"]))
        conn_timeout = int(conn["conn_timeout"])
        tunnel_type = conn["tunnel_type"]

        if tunnel_type.lower() == "udp":
            handler = tunnelc.udp_tunnel
            crypto = self.__udp_crypto
        else:
            handler = tunnelc.tcp_tunnel
            crypto = self.__tcp_crypto

        self.__tunnel_fileno = self.create_handler(
            -1, handler,
            crypto, self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=enable_ipv6
        )

        self.get_handler(self.__tunnel_fileno).create_tunnel((host, port,))

    def tell_tunnel_close(self):
        self.__tunnel_fileno = -1

    def get_server_ip(self, host):
        """获取服务器IP
        :param host:
        :return:
        """
        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        enable_ipv6 = bool(int(self.__configs["connection"]["enable_ipv6"]))
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.__configs["public"]["remote_dns"]]

        if enable_ipv6:
            rs = resolver.query(host, "AAAA")
        else:
            rs = resolver.query(host, "A")

        for anwser in rs:
            return anwser.__str__()

    def myloop(self):
        names = self.__router_timer.get_timeout_names()
        for name in names: self.__del_router(name)

    def set_router(self, host, is_ipv6=False, is_dynamic=True):
        if host in self.__routers: return

        if is_ipv6:
            cmd = "route add -A inet6 -host %s dev %s" % (host, self.__DEVNAME)
        else:
            cmd = "route add -host %s dev %s" % (host, self.__DEVNAME)

        os.system(cmd)

        if not is_dynamic: return

        self.__router_timer.set_timeout(host, self.__ROUTER_TIMEOUT)
        self.__routers[host] = is_ipv6

    def __del_router(self, host):
        if host not in self.__routers: return
        is_ipv6 = self.__routers[host]

        if is_ipv6:
            cmd = "route del -A inet6 -host %s dev %s" % (host, self.__DEVNAME)
        else:
            cmd = "route del -host %s dev %s" % (host, self.__DEVNAME)

        os.system(cmd)
        self.__router_timer.drop(host)
        del self.__routers[host]

    def __update_router_access(self, host):
        """更新路由访问时间
        :param host:
        :return:
        """
        if host not in self.__routers: return
        self.__router_timer.set_timeout(host, self.__ROUTER_TIMEOUT)

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)

        if self.__mode == _MODE_GW:
            self.delete_handler(self.__dgram_fetch_fileno)
            os.chdir("driver")
            os.system("rmmod fdslight_dgram")
            os.chdir("../")
        sys.exit(0)


def __start_service(mode, debug):
    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    config_path = "fdslight_etc/fn_client.ini"
    configs = configfile.ini_parse_from_file(config_path)

    cls = _fdslight_client()
    cls.ioloop(mode, debug, configs)


def __stop_service():
    pid = proc.get_pid(PID_FILE)
    if pid < 0: return

    os.kill(pid, signal.SIGINT)


def __update_host_rules():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("fdslight process not exists")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -m      local | gateway         run as local or gateway
    -u      host_rules              update host rules
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""
    m = ""
    u = ""

    for k, v in opts:
        if k == "-u":
            u = v
            break

        if k == "-m": m = v
        if k == "-d": d = v

    if not d and not m and not u:
        print(help_doc)
        return

    if u and u != "host_rules":
        print(help_doc)
        return
    if u == "host_rules":
        __update_host_rules()
        return

    if d not in ("debug", "start", "stop",):
        print(help_doc)
        return

    if m not in ("local", "gateway"):
        print(help_doc)
        return

    if d in ("start", "debug",):
        debug = False
        if d == "debug": debug = True
        __start_service(m, debug)
        return

    if d == "stop": __stop_service()


if __name__ == '__main__': main()
