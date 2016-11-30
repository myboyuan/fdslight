#!/usr/bin/env python3
import signal, sys, os, getopt

d = os.path.dirname(sys.argv[0])
sys.path.append(d)
pid_dir = "/var/log "

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.timer as timer
import freenet.handler.dns_proxy as dns_proxy
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.checksum as checksum

FDSL_PID_FILE = "fdslight.pid"


def create_pid_file(fname, pid):
    pid_path = "%s/%s" % (pid_dir, fname)
    fd = open(pid_path, "w")
    fd.write(str(pid))
    fd.close()


def get_process_id(fname):
    pid_path = "%s/%s" % (pid_dir, fname)
    if not os.path.isfile(pid_path):
        return -1
    fd = open(pid_path, "r")
    pid = fd.read()
    fd.close()

    return int(pid)


def clear_pid_file():
    for s in [FDSL_PID_FILE, ]:
        pid_path = "%s/%s" % (pid_dir, s)
        if os.path.isfile(pid_path):
            os.remove(pid_path)
        continue
    return


class _fdslight(dispatcher.dispatcher):
    __debug = True
    __raw_socket_fd = -1
    __raw6_socket_fd = -1

    __mode = ""

    __udp_proxy_sessions = {}
    __session_bind = {}

    def __init(self):
        self.create_poll()
        self.__raw_socket_fd = self.create_handler(-1, traffic_pass.traffic_send)
        # elf.__raw6_socket_fd = self.create_handler(-1, traffic_pass.traffic_send, is_ipv6=True)

    @property
    def debug(self):
        return self.__debug

    def init_func(self, mode, debug=True):
        self.__debug = debug
        if debug:
            self.__debug_run(mode)
            return

        self.__run(mode)

    def debug_run(self):
        self.__init()
        if self.__mode == "server":
            self.create_fn_server()
        if self.__mode == "client": self.create_fn_client()

    def run(self):
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

        self.__init()
        if self.__mode == "server": self.reate_fn_server()
        if self.__mode == "client": self.create_fn_client()

        return

    def __create_udp_proxy(self, session_id, saddr, sport, is_ipv6=False):
        """创建UDP代理,以支持cone nat"""
        if session_id not in self.__udp_proxy_sessions: self.__udp_proxy_sessions[session_id] = {}
        t = self.__udp_proxy_sessions[session_id]
        uniq_id = "%s-%s" % (saddr, sport,)

        if uniq_id in t: return
        raw_sock_fileno = self.__raw_socket_fd
        if is_ipv6: raw_sock_fileno = self.__raw6_socket_fd

        fileno = self.create_handler(-1, traffic_pass.udp_proxy,
                                     raw_sock_fileno, session_id,
                                     saddr, sport, is_ipv6=is_ipv6
                                     )
        t[uniq_id] = fileno

    def del_udp_proxy(self, session_id, saddr, sport):
        """删除UDP proxy"""
        if session_id not in self.__udp_proxy_sessions: return
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return
        del t[uniq_id]
        if not t: del self.__udp_proxy_sessions[session_id]

    def __send_ipv4_msg_to_udp_proxy(self, session_id, message):
        length = (message[2] << 3) | message[3]
        msg_len = len(message)
        if msg_len < 21: return
        if length != len(message): return

        ihl = (message[0] & 0x0f) * 4
        offset = ((message[6] & 0x1f) << 5) | message[7]

        # 说明不是第一个数据分包,那么就直接发送给raw socket
        if offset:
            L = list(message)
            checksum.modify_address(b"\0\0\0\0", L, checksum.FLAG_MODIFY_SRC_IP)
            self.send_message_to_handler(self.fileno, self.__raw_socket_fd, bytes(L))
            return

        b, e = (ihl, ihl + 1,)
        sport = (message[b] << 8) | message[e]
        saddr = message.inet_ntoa(message[12:16])

        if not self.__udp_proxy_exists(session_id, saddr, sport):
            self.__create_udp_proxy(session_id, saddr, sport)
        fileno = self.__get_udp_proxy(session_id, saddr, sport)
        self.send_message_to_handler(-1, fileno, message)

    def __send_ipv6_msg_to_udp_proxy(self, session_id, message):
        pass

    def bind_session_id(self, session_id, fileno, other):
        """把session_id和fileno绑定起来"""
        self.__session_bind[session_id] = (fileno, other)

    def unbind_session_id(self, session_id):
        if session_id not in self.__session_bind: return
        del self.__session_bind[session_id]

    def is_bind_session(self, session_id):
        """session是否被绑定"""
        return session_id in self.__session_bind

    def get_bind_session(self, session_id):
        """获取绑定的session的fileno"""
        return self.__session_bind[session_id]

    def send_msg_to_udp_proxy(self, session_id, message):
        """发送消息到UDP PROXY"""
        version = (message[0] & 0xf0) >> 4
        if version not in (4, 6,): return
        if session_id not in self.__session_bind: return
        if version == 4: self.__send_ipv4_msg_to_udp_proxy(session_id, message)
        if version == 6: self.__send_ipv6_msg_to_udp_proxy(session_id, message)

    def __udp_proxy_exists(self, session_id, saddr, sport):
        if session_id not in self.__udp_proxy_sessions: return False
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return False
        return True

    def __get_udp_proxy(self, session_id, saddr, sport):
        if session_id not in self.__udp_proxy_sessions: return None
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return None
        return t[uniq_id]

    def send_msg_to_handler_from_udp_proxy(self, session_id, msg):
        if self.__mode == "client":
            ip_ver = msg[0] & 0xf0 >> 4
            raw_fd = self.__raw_socket_fd
            if ip_ver == 6: raw_fd = self.__raw6_socket_fd
            self.send_message_to_handler(-1, raw_fd, msg)
            return
        if session_id not in self.__session_bind: return
        fileno, _ = self.__session_bind[session_id]
        if not self.handler_exists(fileno): return
        self.ctl_handler(-1, fileno, "msg_from_udp_proxy", session_id, msg)

    def set_mode(self, mode):
        if mode not in ("client", "server",): raise ValueError("the mode must be client or server")
        self.__mode = mode

    def create_fn_server(self):
        """服务端重写这个方法"""
        pass

    def create_fn_client(self):
        """客户端重写这个方法"""
        pass


class fdslightd(_fdslight):
    def __init__(self):
        super(fdslightd, self).__init__()
        self.set_mode("server")

    def create_fn_server(self):
        import freenet.handler.tunnels_tcp as tunnels_tcp
        import freenet.handler.tunnels_udp as tunnels_udp
        import fdslight_etc.fn_server as fns_config
        import freenet.handler.tundev as tundev
        import freenet.lib.static_nat as static_nat

        name = "freenet.tunnels_auth.%s" % fns_config.configs["auth_module"]
        __import__(name)

        m = sys.modules[name]
        auth_module = m.auth()
        auth_module.init()

        if not self.debug: create_pid_file(FDSL_PID_FILE, os.getpid())

        subnet = fns_config.configs["subnet"]
        nat = static_nat.nat(subnet)

        subnet = fns_config.configs["subnet"]

        tun_fd = self.create_handler(-1, tundev.tuns, "fdslight", subnet, nat)
        dns_fd = self.create_handler(-1, dns_proxy.dnsd_proxy, fns_config.configs["dns"])

        args = (tun_fd, -1, dns_fd, auth_module)
        kwargs = {"debug": self.debug}

        self.create_handler(-1, tunnels_udp.tunnels_udp_listener, *args, **kwargs)
        self.create_handler(-1, tunnels_tcp.tunnel_tcp_listener, *args, **kwargs)

        if fns_config.configs["enable_ipv6_tunnel"]:
            kwargs["is_ipv6"] = True
            self.create_handler(-1, tunnels_udp.tunnels_udp_listener, *args, **kwargs)
            self.create_handler(-1, tunnels_tcp.tunnel_tcp_listener, *args, **kwargs)
        return


class fdslightc(_fdslight):
    __tunnel_fd = -1
    __filter_fd = None
    __dns_fd = -1
    __tunnel_ok = False

    __whitelist = None

    __timer = None

    # 过滤器中需要删除的IP
    __wait_del_ips_from_filter = None
    # 过滤器IP保存时间
    __FILTER_IP_LIFETIME = 1200

    def __init__(self):
        super(fdslightc, self).__init__()
        self.set_mode("client")
        self.__timer = timer.timer()
        self.__wait_del_ips_from_filter = []

    def create_fn_client(self):
        import freenet.lib.fdsl_ctl as fdsl_ctl
        import freenet.lib.file_parser as file_parser

        if not self.debug: create_pid_file(FDSL_PID_FILE, os.getpid())

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

        self.__whitelist = file_parser.parse_ip_subnet_file("fdslight_etc/whitelist.txt")
        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")

        self.__dns_fd = self.create_handler(-1, dns_proxy.dnsc_proxy, blacklist, debug=self.debug)

        signal.signal(signal.SIGUSR1, self.__update_blacklist)

    def __update_blacklist(self, signum, frame):
        import freenet.lib.file_parser as file_parser
        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")
        self.get_handler(self.__dns_fd).update_blacklist(blacklist)

    def tunnel_fail(self):
        """客户端隧道建立失败"""
        self.__tunnel_ok = False

    def tunnel_ok(self):
        """客户端隧道建立成功"""
        self.__tunnel_ok = True

    def tunnel_is_ok(self):
        return self.__tunnel_ok

    def open_tunnel(self):
        import fdslight_etc.fn_client as fnc_config
        import freenet.handler.tunnelc_tcp as tunnelc_tcp
        import freenet.handler.tunnelc_udp as tunnelc_udp

        tunnel_type = fnc_config.configs["tunnel_type"].lower()
        args = (self.__dns_fd, self.__raw_socket_fd, self.__raw6_socket_fd, self.__whitelist)
        kwargs = {"debug": self.debug, "is_ipv6": False}

        if tunnel_type not in ("tcp6", "udp6", "tcp", "udp",): raise ValueError("not support tunnel type")
        if tunnel_type in ("tcp6", "udp6",): kwargs["is_ipv6"] = True

        if tunnel_type in ("udp", "udp6"):
            tunnel = tunnelc_udp.tunnelc_udp
        else:
            tunnel = tunnelc_tcp.tunnelc_tcp
        self.__tunnel_fd = self.create_handler(-1, tunnel, *args, **kwargs)

    def is_need_send_udp_to_tunnel(self, saddr):
        """是否需要发送UDP流量到隧道"""


        return

    def set_filter_fd(self, fileno):
        self.__filter_fd = fileno

    def update_filter_ip_access_time(self, n):
        """更新过滤器IP访问时间"""
        self.__timer.set_timeout(n, self.__FILTER_IP_LIFETIME)

    def myloop(self):
        import freenet.lib.fdsl_ctl as fdsl_ctl
        if not self.__tunnel_ok: return

        for ip in self.__timer.get_timeout_names():
            if not self.__timer.exists(ip): continue
            self.__timer.drop(ip)
            self.__wait_del_ips_from_filter.append(ip)
        while 1:
            try:
                ip = self.__wait_del_ips_from_filter(0)
            except IndexError:
                break
            fdsl_ctl.tf_record_del(self.__filter_fd, ip)
        return


def stop_service():
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1: return
    os.kill(pid, signal.SIGINT)


def update_blacklist():
    """更新黑名单"""
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1:
        print("cannot found fdslight process")
        return
    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -u blacklist                update blacklist
    -m client | server          client or server
    -d stop | start | debug     stop,start,debug
    -h                          print help
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    m = ""
    d = ""
    u = ""

    size = len(opts)

    for k, v in opts:
        if k == "-d":
            d = v
        if k == "-m":
            m = v
        if k == "-u":
            u = v
        if k == "-h":
            print(help_doc)
            return
        continue

    if u not in ("blacklist", "whitelist",) and u != "":
        print(help_doc)
        return

    if u and size != 1:
        print(help_doc)
        return

    if u == "blacklist" and size == 1:
        update_blacklist()
        return

    if not m or not d:
        print(help_doc)
        return

    if d not in ["stop", "start", "debug"]:
        print(help_doc)
        return

    if m not in ["client", "server"]:
        print(help_doc)
        return

    if d == "stop":
        stop_service()
        return

    debug = False
    if d == "debug": debug = True

    if m == "server":
        fdslight_ins = fdslightd()
    else:
        fdslight_ins = fdslightc()

    try:
        fdslight_ins.ioloop(m, debug=debug)
    except KeyboardInterrupt:
        clear_pid_file()
        sys.stdout.flush()
        sys.stdout.close()
        sys.stderr.close()

    return


if __name__ == '__main__': main()
