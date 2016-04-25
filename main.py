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
import freenet.lib.ipaddr as ipaddr
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

    __time = 0
    # 重新建立连接的时间间隔
    __RECONNECT_TIMEOUT = 60

    def __create_fn_server(self):

        name = "freenet.tunnels.%s" % fns_config.configs["udp_tunnel"]
        __import__(name)
        m = sys.modules[name]
        if not self.__debug: create_pid_file(FDSL_PID_FILE, os.getpid())

        subnet = fns_config.configs["subnet"]
        ip_pool = ipaddr.ip4addr(*subnet)

        self.create_poll()
        subnet = fns_config.configs["subnet"]

        tun_fd = self.create_handler(-1, tundev.tuns, "fdslight", subnet)
        dns_fd = self.create_handler(-1, dns_proxy.dnsd_proxy, fns_config.configs["dns"])
        raw_socket_fd = self.create_handler(-1, traffic_pass.traffic_send)

        self.create_handler(-1, m.tunnel, tun_fd, dns_fd, raw_socket_fd, ip_pool, debug=self.__debug)
        self.create_handler(-1, ts_tcp_base._tunnel_tcp_listen,
                            tun_fd, dns_fd, raw_socket_fd, ip_pool,
                            debug=self.__debug)

    def __create_fn_client(self):
        if not self.__debug: create_pid_file(FDSL_PID_FILE, os.getpid())
        self.create_poll()

        os.chdir("driver")
        if not os.path.isfile("fdslight.ko"):
            print("you must install this software")
            sys.exit(-1)

        path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        if os.path.exists(path):
            os.system("rmmod fdslight")

        os.system("insmod fdslight.ko")

        os.chdir("../")

        whitelist = file_parser.parse_ip_subnet_file("fdslight_etc/whitelist.txt")
        blacklist = file_parser.parse_host_file("fdslight_etc/blacklist.txt")

        self.__dnsc_fd = self.create_handler(-1, dns_proxy.dns_proxy, blacklist, debug=self.__debug)

        name_tcp = "freenet.tunnelc.%s" % fnc_config.configs["tcp_tunnel"]
        name_udp = "freenet.tunnelc.%s" % fnc_config.configs["udp_tunnel"]

        if fnc_config.configs["tunnel_type"].lower() == "udp":
            name = name_udp
        else:
            name = name_tcp

        __import__(name)
        self.__tunnelc = sys.modules[name]
        self.create_handler(-1, self.__tunnelc.tunnel, self.__dnsc_fd, whitelist, debug=self.__debug)

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
        if self.__need_establish_ctunnel:
            t = time.time() - self.__time
            if t < self.__RECONNECT_TIMEOUT: return
            self.__time = time.time()
            self.__need_establish_ctunnel = False
            self.create_handler(-1, self.__tunnelc.tunnel, self.__dnsc_fd, [],
                                debug=self.__debug)
        return


def stop_service():
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1: return
    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """

    -m
    client | server
    -d
    stop | start | debug
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    m = ""
    d = ""
    for k, v in opts:
        if k == "-d":
            d = v
        if k == "-m":
            m = v
        continue

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


if __name__ == '__main__':
    main()
