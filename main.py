#!/usr/bin/env python3
import signal, sys, os, getopt

d = os.path.dirname(sys.argv[0])
sys.path.append(d)
pid_dir = "/tmp"

import pywind.evtframework.evt_dispatcher as dispatcher
import fdslight_etc.fn_server as fns_config
import fdslight_etc.fn_client as fnc_config
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.file_parser as file_parser
import freenet.handler.tunnels_tcp_base as ts_tcp_base
import freenet.handler.tundev as tundev
import freenet.handler.dns_proxy as dns_proxy
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.static_nat as static_nat
import freenet.lib.checksum as checksum

import time

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


class fdslight(dispatcher.dispatcher):
    __debug = True
    # 客户端是否需要建立隧道,用于客户端模式
    __need_establish_ctunnel = False
    # 客户端DNS socket文件描述符
    __dnsc_fd = -1
    __tunnelc = None
    __tunnelc_fd = -1

    __raw_socket_fd = -1
    __raw6_socket_fd = -1

    __time = 0
    # 重新建立连接的时间间隔
    __RECONNECT_TIMEOUT = 60
    __mode = ""

    __udp_proxy_sessions = {}
    __session_bind = {}

    def __create_fn_server(self):

        name = "freenet.tunnels.%s" % fns_config.configs["udp_tunnel"]
        __import__(name)
        m = sys.modules[name]
        if not self.__debug: create_pid_file(FDSL_PID_FILE, os.getpid())

        subnet = fns_config.configs["subnet"]
        nat = static_nat.nat(subnet)

        self.create_poll()
        subnet = fns_config.configs["subnet"]

        tun_fd = self.create_handler(-1, tundev.tuns, "fdslight", subnet)
        dns_fd = self.create_handler(-1, dns_proxy.dnsd_proxy, fns_config.configs["dns"])
        raw_socket_fd = self.create_handler(-1, traffic_pass.traffic_send)

        self.create_handler(-1, m.tunnel, tun_fd, dns_fd, nat, debug=self.__debug)
        self.create_handler(-1, ts_tcp_base._tunnel_tcp_listen,
                            tun_fd, dns_fd, nat,
                            debug=self.__debug)
        self.__mode = "server"

    def __create_fn_client(self):
        if not self.__debug: create_pid_file(FDSL_PID_FILE, os.getpid())
        self.create_poll()

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

        whitelist = file_parser.parse_ip_subnet_file("fdslight_etc/whitelist.txt")
        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")

        self.__dnsc_fd = self.create_handler(-1, dns_proxy.dnsc_proxy, blacklist, debug=self.__debug)

        self.__raw_socket_fd = self.create_handler(-1, traffic_pass.traffic_send)
        self.__raw6_socket_fd = self.create_handler(-1, traffic_pass.traffic_send, is_ipv6=True)

        name_tcp = "freenet.tunnelc.%s" % fnc_config.configs["tcp_tunnel"]
        name_udp = "freenet.tunnelc.%s" % fnc_config.configs["udp_tunnel"]

        if fnc_config.configs["tunnel_type"].lower() == "udp":
            name = name_udp
        else:
            name = name_tcp

        __import__(name)
        self.__tunnelc = sys.modules[name]
        self.__tunnelc_fd = self.create_handler(-1, self.__tunnelc.tunnel, self.__dnsc_fd, self.__raw_socket_fd,
                                                whitelist, debug=self.__debug)

        signal.signal(signal.SIGUSR1, self.__update_blacklist)
        self.__mode = "client"

    def __update_blacklist(self, signum, frame):
        if self.__mode != "client": return

        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")
        self.get_handler(self.__dnsc_fd).update_blacklist(blacklist)

    def init_func(self, mode, debug=True):
        self.__debug = debug
        if debug:
            self.__debug_run(mode)
            return

        self.__run(mode)

    def __debug_run(self, mode):
        if mode == "server":
            self.__create_fn_server()
        if mode == "client": self.__create_fn_client()

    def __run(self, mode):
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

        if mode == "server": self.__create_fn_server()
        if mode == "client": self.__create_fn_client()

        return

    def ctunnel_fail(self):
        """客户端隧道建立失败"""
        self.__need_establish_ctunnel = True
        self.__time = time.time()

    def ctunnel_ok(self):
        """客户端隧道建立成功"""
        self.__need_establish_ctunnel = False

    def myloop(self):
        return

    def open_ctunnel(self):
        pass

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

    def bind_session_id(self, session_id, fileno):
        """把session_id和fileno绑定起来"""
        self.__session_bind[session_id] = fileno

    def unbind_session_id(self, session_id):
        if session_id not in self.__session_bind: return
        del self.__session_bind[session_id]

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
        if session_id not in self.__session_bind: return
        fileno = self.__session_bind[session_id]
        if not self.handler_exists(fileno): return
        self.ctl_handler(-1, fileno, "msg_from_udp_proxy", session_id, msg)


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

    fdslight_ins = fdslight()

    try:
        fdslight_ins.ioloop(m, debug=debug)
    except KeyboardInterrupt:
        clear_pid_file()
        sys.stdout.flush()
        sys.stdout.close()
        sys.stderr.close()

    return


if __name__ == '__main__': main()
