#!/usr/bin/env python3

import sys, os, getopt, signal, random

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg

import freenet.lib.proc as proc
import freenet.handlers.socks2https_client as socks2https_client
import freenet.handlers.socks5https_relay as socks2https_relay
import freenet.handlers.socks5https_dns as socks2https_dns
import freenet.lib.host_match as host_match
import freenet.lib.ip_match as ip_match
import freenet.lib.file_parser as file_parser
import freenet.lib.utils as utils

PID_PATH = "/tmp/s2hsc.pid"


class serverd(dispatcher.dispatcher):
    __cfg_path = None
    __host_rules_path = None
    __ip_rules_path = None
    __udp_src_proxy_path = None

    __socks5http_listen_fd = None
    __socks5http_listen_fd6 = None

    __relay_listen_fd = None
    __relay_listen_fd6 = None

    __relay_info = None

    __convert_fd = None

    __debug = None

    __configs = None

    __client_conn_timeout = None
    __client_heartbeat_time = None

    __socks5_bind_ip = None
    __socks5_bind_ipv6 = None

    __dnsserver_fd = None
    __dnsserver_fd6 = None

    __packet_id_map = None
    __debug = None

    __domain_match = None
    __ip_match = None
    __udp_src_match = None

    def init_func(self, mode, with_dnsserver=False, debug=True):
        self.__packet_id_map = {}
        self.__relay_info = {}

        if mode == "proxy":
            self.__cfg_path = "%s/fdslight_etc/s2hsc.ini" % BASE_DIR
            self.__host_rules_path = "%s/fdslight_etc/host_rules.txt" % BASE_DIR
            self.__ip_rules_path = "%s/fdslight_etc/ip_rules.txt" % BASE_DIR
            self.__udp_src_proxy_path = "%s/fdslight_etc/udp_src_proxy.txt" % BASE_DIR
        else:
            self.__cfg_path = "%s/fdslight_etc/s2hsr.ini" % BASE_DIR

        self.__debug = debug

        self.__socks5http_listen_fd = -1
        self.__socks5http_listen_fd6 = -1

        self.__dnsserver_fd = -1
        self.__dnsserver_fd6 = -1

        self.__convert_fd = -1

        self.__debug = debug

        self.create_poll()

        if not debug: signal.signal(signal.SIGINT, self.__exit)

        self.__configs = cfg.ini_parse_from_file(self.__cfg_path)

        if mode == "relay":
            if not debug: signal.signal(signal.SIGUSR1, self.__update_relay)
            self.create_relay_service()

        if mode == "proxy":
            if not debug: signal.signal(signal.SIGUSR1, self.__update_rules)
            self.__domain_match = host_match.host_match()
            self.__ip_match = ip_match.ip_match()
            self.__udp_src_match = ip_match.ip_match()
            # 首先第一次先更新规则
            self.__update_rules(None, None)
            if with_dnsserver: self.create_dns_service()
            self.create_socks_http_service()

    def release(self):
        if self.__socks5http_listen_fd > 0:
            self.delete_handler(self.__socks5http_listen_fd)
        if self.__socks5http_listen_fd6 > 0:
            self.delete_handler(self.__socks5http_listen_fd6)
        if self.__dnsserver_fd > 0:
            self.delete_handler(self.__dnsserver_fd)
        if self.__dnsserver_fd6 > 0:
            self.delete_handler(self.__dnsserver_fd6)

        dels = []
        for fd, v in self.__relay_info: dels.append(fd)
        for fd in dels: self.delete_handler(fd)

    def __exit(self, signum, frame):
        self.release()
        os.remove(PID_PATH)
        sys.exit(0)

    def __update_relay(self, signum, frame):
        dels = []
        for fd, v in self.__relay_info: dels.append(fd)
        for fd in dels: self.delete_handler(fd)
        self.create_relay_service()

    def __update_rules(self, signum, frame):
        """更新白名单规则
        :param signum:
        :param frame:
        :return:
        """
        host_rules = file_parser.parse_host_file(self.__host_rules_path)
        ip_rules = file_parser.parse_ip_subnet_file(self.__ip_rules_path)
        udp_src_rules = file_parser.parse_ip_subnet_file(self.__udp_src_proxy_path)

        for rule in host_rules: self.__domain_match.add_rule(rule)
        for subnet, prefix in ip_rules:
            rs = self.__ip_match.add_rule(subnet, prefix)
            if not rs:
                sys.stderr.write("wrong ip format at %s/%s from %s" % (subnet, prefix, self.__ip_rules_path))
                sys.stderr.flush()
            ''''''
        for subnet, prefix in udp_src_rules:
            rs = self.__udp_src_match.add_rule(subnet, prefix)
            if not rs:
                sys.stderr.write("wrong ip format at %s/%s from %s" % (subnet, prefix, self.__udp_src_proxy_path))
                sys.stderr.flush()
            ''''''
        return

    def match_ip(self, ipaddr, is_ipv6=False, is_ip_host=False):
        return self.__ip_match.match(ipaddr, is_ipv6=is_ipv6, is_host=is_ip_host)

    def match_domain(self, host):
        return self.__domain_match.match(host)

    def match_udp_src_ip(self, ipaddr, is_ipv6=False):
        return self.__udp_src_match.match(ipaddr, is_ipv6=is_ipv6)

    def match_host_rule_add(self, host):
        self.__ip_match.add_ip_host(host)

    def create_socks_http_service(self):
        config = cfg.ini_parse_from_file(self.__cfg_path)

        c = config.get("socks5_http_listen", {})
        enable_ipv6 = bool(int(c.get("enable_ipv6", 0)))
        listen_ip = c.get("listen_ip", "0.0.0.0")
        listen_ipv6 = c.get("listen_ipv6", "::")
        port = int(c.get("port", 8800))

        self.__socks5_bind_ip = listen_ip
        self.__socks5_bind_ipv6 = listen_ipv6

        if port < 0 or port > 65535:
            raise ValueError("wrong port number from s2hsc.ini")

        conn_timeout = int(c.get("conn_timeout", 60))
        if conn_timeout < 1:
            raise ValueError("wrong conn_timeout value from s2hsc.ini")

        self.__client_conn_timeout = conn_timeout

        self.__socks5http_listen_fd = self.create_handler(
            -1, socks2https_client.http_socks5_listener, (listen_ip, port), is_ipv6=False
        )
        if enable_ipv6:
            self.__socks5http_listen_fd6 = self.create_handler(
                -1, socks2https_client.http_socks5_listener, (listen_ipv6, port), is_ipv6=True
            )

    def parse_relay_config(self, name, py_obj):
        """解析中继配置
        :param name:
        :param py_obj:
        :return:
        """
        o = py_obj[name]

        listen_ip = o.get("listen_ip")

        if not utils.is_ipv6_address(listen_ip) and not utils.is_ipv4_address(listen_ip): return None
        if utils.is_ipv4_address(listen_ip):
            is_ipv6 = False
        else:
            is_ipv6 = True

        try:
            port = int(o.get("port", 8800))
        except ValueError:
            return None
        if port < 1 or port > 65535:
            return None
        try:
            conn_timeout = o.get("conn_timeout", 120)
        except ValueError:
            return None

        if conn_timeout < 1: return None

        redir_host = o.get("redirect_host", "")
        try:
            redir_port = int(o.get("redirect_port", 0))
        except ValueError:
            return None

        if redir_port < 1 or redir_port > 65535: return None

        return {
            "is_ipv6": is_ipv6,
            "listen_ip": listen_ip,
            "port": port,
            "conn_timeout": conn_timeout,
            "redirect_host": redir_host,
            "redirect_port": redir_port
        }

    def create_dns_service(self):
        config = cfg.ini_parse_from_file(self.__cfg_path)
        c = config.get("dns_listen", {})

        try:
            enable_ipv6 = bool(int(c.get("enable_ipv6", 0)))
        except ValueError:
            sys.stderr.write("wrong dns config A")
            sys.stderr.flush()
            return

        listen_ip = c.get("listen_ip", "0.0.0.0")
        listen_ipv6 = c.get("listen_ipv6", "::")

        ns_no_proxy_v4 = c.get("nameserver_no_proxy_v4", "223.5.5.5")
        ns_with_proxy_v4 = c.get("nameserver_with_proxy_v4", "8.8.8.8")

        ns_no_proxy_v6 = c.get("nameserver_no_proxy_v6", "2001:4860:4860::8888")
        ns_with_proxy_v6 = c.get("nameserver_with_proxy_v6", "2001:4860:4860::8844")

        if not utils.is_ipv4_address(listen_ip) or not utils.is_ipv4_address(
                ns_no_proxy_v4) or not utils.is_ipv4_address(ns_with_proxy_v4):
            sys.stderr.write("wrong dns config B")
            sys.stderr.flush()
            return

        if not utils.is_ipv6_address(listen_ipv6) or not utils.is_ipv6_address(
                ns_no_proxy_v6) or not utils.is_ipv6_address(
            ns_with_proxy_v6):
            sys.stderr.write("wrong dns config C")
            sys.stderr.flush()
            return

        self.__dnsserver_fd = self.create_handler(-1, socks2https_dns.dns_proxy, (listen_ip, 53,), ns_no_proxy_v4,
                                                  ns_with_proxy_v4)
        if enable_ipv6:
            self.__dnsserver_fd6 = self.create_handler(-1, socks2https_dns.dns_proxy, (listen_ipv6, 53,),
                                                       ns_no_proxy_v6, ns_with_proxy_v6)

    def create_relay_service(self):
        configs = cfg.ini_parse_from_file(self.__cfg_path)
        for name in configs:
            o = self.parse_relay_config(name, configs)
            if not o:
                sys.stderr.write("wrong config name about %s" % name)
                continue
            listen_ip = o["listen_ip"]
            port = o["port"]
            is_ipv6 = o["is_ipv6"]
            timeout = o["conn_timeout"]
            redir_host = o["redirect_host"]
            redir_port = o["redirect_port"]
            fd = self.create_handler(-1, socks2https_relay.listener, (listen_ip, port), name, conn_timeout=timeout,
                                     is_ipv6=is_ipv6)
            self.__relay_info[name] = [fd, (redir_host, redir_port,)]

    def del_relay_service(self, name):
        if name not in self.__relay_info: return
        del self.__relay_info[name]

    def get_relay_service(self, name):
        return self.__relay_info.get(name, None)

    def create_convert_client(self):
        configs = cfg.ini_parse_from_file(self.__cfg_path)

        serv_cfg = configs.get("server_connection", {})
        if not serv_cfg:
            raise SystemError("s2hsc.ini configure file failed")
        enable_ipv6 = bool(int(serv_cfg.get("enable_ipv6", 0)))

        host = serv_cfg.get("host", "")
        port = int(serv_cfg.get("port", 443))
        if port < 0 or port > 65535:
            raise ValueError("wrong port number from s2hsc.ini")

        conn_timeout = int(serv_cfg.get("conn_timeout", 100))

        if conn_timeout < 1:
            raise ValueError("wrong conn_timeout value from s2hsc.ini")

        heartbeat_timeout = int(serv_cfg.get("heartbeat_timeout", 30))

        if heartbeat_timeout < 1:
            raise ValueError("wrong heartbeat_time value from s2hsc.ini")

        self.__client_heartbeat_time = heartbeat_timeout

        path = serv_cfg.get("http_path", "/")
        user = serv_cfg.get("user", "")
        passwd = serv_cfg.get("passwd", "")

        self.__convert_fd = self.create_handler(-1, socks2https_client.convert_client, (host, port), path, user, passwd,
                                                is_ipv6=enable_ipv6)

    def delete_handler(self, fd):
        super(serverd, self).delete_handler(fd)
        # 注意,这里非常重要,因为convert_fd是在变化的,而程序中会fd会频繁释放创建
        # 如果convert_fd不设置成-1,那么会导致发送给fd的数据发送到其他地方
        if fd == self.__convert_fd: self.__convert_fd = -1

    def alloc_packet_id(self, fd):
        n = 1
        while 1:
            n = random.randint(1, 0xffffffff - 1)
            if n in self.__packet_id_map: continue
            break
        self.__packet_id_map[n] = fd
        return n

    def free_packet_id(self, packet_id):
        if packet_id in self.__packet_id_map:
            del self.__packet_id_map[packet_id]

    def send_conn_frame(self, frame_type, packet_id, host, port, addr_type, data=b""):
        if not self.handler_exists(self.__convert_fd):
            self.create_convert_client()
        if not self.handler_exists(self.__convert_fd): return
        if packet_id not in self.__packet_id_map: return

        self.get_handler(self.__convert_fd).send_conn_request(
            frame_type, packet_id, host, port, addr_type, data=data
        )

    def send_tcp_data(self, packet_id, byte_data):
        if not byte_data: return
        # 连接已经断开,那么丢弃tcp数据包
        if not self.handler_exists(self.__convert_fd): return
        # 数据包ID不存在,那么就丢弃数据包
        if packet_id not in self.__packet_id_map: return
        self.get_handler(self.__convert_fd).send_tcp_data(packet_id, byte_data)

    def handle_udp_udplite_data(self, packet_id, address, port, byte_data):
        if not byte_data: return
        if packet_id not in self.__packet_id_map: return
        fd = self.__packet_id_map[packet_id]
        try:
            self.get_handler(fd).handle_udp_udplite_data((address, port), byte_data)
        except AttributeError:
            pass

    def handle_tcp_data(self, packet_id, byte_data):
        if packet_id not in self.__packet_id_map: return
        fd = self.__packet_id_map[packet_id]
        self.send_message_to_handler(-1, fd, byte_data)

    def handle_conn_state(self, packet_id, err_code):
        """处理连接状态
        :param packet_id:
        :param err_code:
        :return:
        """
        if packet_id not in self.__packet_id_map: return
        fd = self.__packet_id_map[packet_id]

        if err_code:
            self.get_handler(fd).tell_close()
        else:
            self.get_handler(fd).tell_conn_ok()

    def tell_close_for_all(self):
        fds = []
        #  注意这里一定要先放到集合内再删除,否则可能发现在遍历的时候删除映射对象情况导致抛出异常
        for k, v in self.__packet_id_map.items():
            fds.append(v)
        for fd in fds:
            self.get_handler(fd).tell_close()

    @property
    def client_conn_timeout(self):
        return self.__client_conn_timeout

    @property
    def client_heartbeat_time(self):
        return self.__client_heartbeat_time

    @property
    def socks5_listen_ip(self):
        return self.__socks5_bind_ip

    @property
    def socks5_listen_ipv6(self):
        return self.__socks5_bind_ipv6

    @property
    def debug(self):
        return self.__debug

    def myloop(self):
        self.__ip_match.auto_delete()


def update_rules():
    pid = proc.get_pid(PID_PATH)
    if pid < 0:
        sys.stderr.write("not found process\r\n")
        sys.stderr.flush()
        return
    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -m      relay | proxy           relay mode,proxy mode or all mode
    -u                              update rule files
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:d:u", ["with-dnsserver"])
    except getopt.GetoptError:
        print(help_doc)
        return

    d = None
    m = None
    u = None
    enable_dns = False

    if sys.platform.find("win32") > -1:
        is_windows = True
    else:
        is_windows = False

    for k, v in opts:
        if k == "-d": d = v
        if k == "-m": m = v
        if k == "-u": u = True
        if k == "--with-dnsserver": enable_dns = True

    if u and (d or m):
        print(help_doc)
        return

    if u and enable_dns:
        print(help_doc)
        return

    if u:
        update_rules()
        return

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    if is_windows and d in ("start", "stop",):
        sys.stderr.write("windows only support -d debug")
        return

    if m not in ("relay", "proxy"):
        print(help_doc)
        return

    if d == "stop":
        pid = proc.get_pid(PID_PATH)
        if pid > 0: os.kill(pid, signal.SIGINT)
        return

    debug = True

    if d == "start":
        if os.path.exists(PID_PATH):
            print("the process s2hsc exists,please delete %s or kill it at first" % PID_PATH)
            return
        debug = False
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)

        proc.write_pid(PID_PATH)

    cls = serverd()
    try:
        cls.ioloop(m, with_dnsserver=enable_dns, debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
