#!/usr/bin/env python3

import sys, os

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

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
import freenet.handlers.traffic_pass as traffic_pass
import freenet.lib.logging as logging
import dns.resolver

_MODE_GW = 1
_MODE_LOCAL = 2

PID_FILE = "/tmp/fdslight.pid"
LOG_FILE = "/tmp/fdslight.log"
ERR_FILE = "/tmp/fdslight_error.log"


class _fdslight_client(dispatcher.dispatcher):
    # 路由超时时间
    __ROUTER_TIMEOUT = 1200

    __routers = None

    __router_timer = None

    __DEVNAME = "fdslight"

    __configs = None

    __mode = 0

    __mbuf = None

    __tunnel_fileno = -1

    __dns_fileno = -1

    __dns_listen6 = -1
    __tundev_fileno = -1

    __session_id = None

    __debug = False

    __tcp_crypto = None
    __udp_crypto = None
    __crypto_configs = None

    __support_ip4_protocols = (1, 6, 17, 132, 136,)
    __support_ip6_protocols = (6, 17, 58, 132, 136,)

    __dgram_fetch_fileno = -1

    # 是否开启IPV6流量
    __enable_ipv6_traffic = False

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

        self.__enable_ipv6_traffic = bool(int(public["enable_ipv6_traffic"]))

        is_ipv6 = utils.is_ipv6_address(public["remote_dns"])

        if self.__mode == _MODE_GW:
            self.__dns_fileno = self.create_handler(
                -1, dns_proxy.dnsc_proxy,
                gateway["dnsserver_bind"], debug=debug, server_side=True, is_ipv6=False
            )
            self.get_handler(self.__dns_fileno).set_parent_dnsserver(public["remote_dns"], is_ipv6=is_ipv6)

            if self.__enable_ipv6_traffic:
                self.__dns_listen6 = self.create_handler(
                    -1, dns_proxy.dnsc_proxy,
                    gateway["dnsserver_bind6"], debug=debug, server_side=True, is_ipv6=True
                )
                self.get_handler(self.__dns_listen6).set_parent_dnsserver(public["remote_dns"], is_ipv6=is_ipv6)
        else:
            self.__dns_fileno = self.create_handler(
                -1, dns_proxy.dnsc_proxy,
                public["remote_dns"], debug=debug, server_side=False
            )

        self.__set_host_rules(None, None)

        if self.__mode == _MODE_GW:
            self.__load_kernel_mod()
            udp_global = bool(int(gateway["dgram_global_proxy"]))
            if udp_global:
                self.__dgram_fetch_fileno = self.create_handler(
                    -1, traffic_pass.traffic_read,
                    self.__configs["gateway"], enable_ipv6=self.__enable_ipv6_traffic
                )
            ''''''
        else:
            local = configs["local"]
            vir_dns = local["virtual_dns"]
            vir_dns6 = local["virtual_dns6"]

            self.set_router(vir_dns, is_ipv6=False, is_dynamic=False)
            if self.__enable_ipv6_traffic: self.set_router(vir_dns6, is_ipv6=True, is_dynamic=False)

        conn = configs["connection"]

        m = "freenet.lib.crypto.%s" % conn["crypto_module"]
        try:
            self.__tcp_crypto = importlib.import_module("%s.%s_tcp" % (m, conn["crypto_module"]))
            self.__udp_crypto = importlib.import_module("%s.%s_udp" % (m, conn["crypto_module"]))
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        crypto_fpath = "%s/fdslight_etc/%s" % (BASE_DIR, conn["crypto_configfile"])

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
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")
        ''''''

        signal.signal(signal.SIGUSR1, self.__set_host_rules)

    def __load_kernel_mod(self):
        ko_file = "%s/driver/fdslight_dgram.ko" % BASE_DIR

        if not os.path.isfile(ko_file):
            print("you must install this software")
            sys.exit(-1)

        fpath = "%s/fdslight_etc/kern_version" % BASE_DIR
        if not os.path.isfile(fpath):
            print("you must install this softwar")
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

        if self.__enable_ipv6_traffic:
            os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")

        os.system("insmod %s" % ko_file)

    def handle_msg_from_tundev(self, message):
        """处理来TUN设备的数据包
        :param message:
        :return:
        """
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()

        if ip_ver not in (4, 6,): return

        action = proto_utils.ACT_DATA
        is_ipv6 = False

        if ip_ver == 4:
            self.__mbuf.offset = 9
            nexthdr = self.__mbuf.get_part(1)
            self.__mbuf.offset = 16
            byte_daddr = self.__mbuf.get_part(4)
            fa = socket.AF_INET
        else:
            is_ipv6 = True
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
                self.get_handler(self.__dns_fileno).dnsmsg_from_tun(saddr, daddr, sport, rs, is_ipv6=is_ipv6)
                return

        self.__update_router_access(sts_daddr)
        self.send_msg_to_tunnel(action, message)

    def handle_msg_from_dgramdev(self, message):
        """处理来自fdslight dgram设备的数据包
        :param message:
        :return:
        """
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        is_ipv6 = False

        if ip_ver == 4:
            self.__mbuf.offset = 16
            fa = socket.AF_INET
            n = 4
        else:
            self.__mbuf.offset = 24
            fa = socket.AF_INET6
            n = 16
            is_ipv6 = True

        byte_daddr = self.__mbuf.get_part(n)
        sts_daddr = socket.inet_ntop(fa, byte_daddr)

        if sts_daddr not in self.__routers:
            self.set_router(sts_daddr, timeout=190, is_ipv6=is_ipv6, is_dynamic=True)
        else:
            self.__update_router_access(sts_daddr, timeout=190)
        self.send_msg_to_tunnel(proto_utils.ACT_DATA, message)

    def handle_msg_from_tunnel(self, seession_id, action, message):
        if seession_id != self.session_id: return
        if action not in proto_utils.ACTS: return

        if action == proto_utils.ACT_DNS:
            self.get_handler(self.__dns_fileno).msg_from_tunnel(message)
            return
        self.__mbuf.copy2buf(message)
        ip_ver = self.__mbuf.ip_version()
        if ip_ver not in (4, 6,): return

        self.send_msg_to_tun(message)

    def send_msg_to_other_dnsservice_for_dns_response(self, message, is_ipv6=False):
        """当启用IPV4和IPv6双协议栈的时候
        此函数的作用是两个局域网DNS服务相互发送消息
        :param message: 
        :param is_ipv6:发送的目标是否是IPv6 DNS服务 
        :return: 
        """
        # 没有开启IPv6的时候,禁止向另外的DNS服务发送消息
        if not self.__enable_ipv6_traffic: return
        if is_ipv6:
            fileno = self.__dns_listen6
        else:
            fileno = self.__dns_fileno

        self.send_message_to_handler(-1, fileno, message)

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
        fpath = "%s/fdslight_etc/host_rules.txt" % BASE_DIR

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
            ipaddr = anwser.__str__()
            break
        if self.__mode == _MODE_GW: self.__set_tunnel_ip(ipaddr)

        return ipaddr

    def myloop(self):
        names = self.__router_timer.get_timeout_names()
        for name in names: self.__del_router(name)

    def set_router(self, host, timeout=None, is_ipv6=False, is_dynamic=True):
        if host in self.__routers: return

        # 如果禁止了IPV6流量,那么不设置IPV6路由
        if not self.__enable_ipv6_traffic and is_ipv6: return
        if is_ipv6:
            cmd = "route add -A inet6 %s/128 dev %s" % (host, self.__DEVNAME)
        else:
            cmd = "route add -host %s dev %s" % (host, self.__DEVNAME)

        os.system(cmd)

        if not is_dynamic: return

        if not timeout:
            timeout = self.__ROUTER_TIMEOUT
        self.__router_timer.set_timeout(host, timeout)
        self.__routers[host] = is_ipv6

    def __del_router(self, host):
        if host not in self.__routers: return
        is_ipv6 = self.__routers[host]

        if is_ipv6:
            cmd = "route del -A inet6 %s/128 dev %s" % (host, self.__DEVNAME)
        else:
            cmd = "route del -host %s dev %s" % (host, self.__DEVNAME)

        os.system(cmd)
        self.__router_timer.drop(host)
        del self.__routers[host]

    def __update_router_access(self, host, timeout=None):
        """更新路由访问时间
        :param host:
        :param timeout:如果没有指定,那么使用默认超时
        :return:
        """
        if host not in self.__routers: return
        if not timeout:
            timeout = self.__ROUTER_TIMEOUT
        self.__router_timer.set_timeout(host, timeout)

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)

        if self.__mode == _MODE_GW:
            self.delete_handler(self.__dgram_fetch_fileno)
            os.chdir("%s/driver" % BASE_DIR)
            os.system("rmmod fdslight_dgram")
            os.chdir("../")
        sys.exit(0)

    def __set_tunnel_ip(self, ip):
        """设置隧道IP地址
        :param ip:
        :return:
        """
        if self.__mode == _MODE_GW:
            self.get_handler(self.__dgram_fetch_fileno).set_tunnel_ip(ip)
        return


def __start_service(mode, debug):
    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    config_path = "%s/fdslight_etc/fn_client.ini" % BASE_DIR

    configs = configfile.ini_parse_from_file(config_path)

    cls = _fdslight_client()

    if debug:
        cls.ioloop(mode, debug, configs)
        return
    try:
        cls.ioloop(mode, debug, configs)
    except:
        logging.print_error()


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
