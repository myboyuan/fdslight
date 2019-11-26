#!/usr/bin/env python3

import sys, os, getopt, signal, json

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg

import freenet.handlers.socks2https_server as socks2https_server
import freenet.lib.proc as proc

PID_PATH = "/tmp/s2hss.pid"
LOG_FILE = "%s/s2hss.log" % BASE_DIR
ERR_FILE = "%s/s2hss_err.log" % BASE_DIR

class serverd(dispatcher.dispatcher):
    __cfg_path = None
    __auth_path = None

    __listen_fd = None
    __listen_fd6 = None

    __debug = None

    __conn_timeout = None
    __heartbeat_timeout = None

    __listen_ip = None
    __listen_ipv6 = None
    __enable_ipv6 = None

    def init_func(self, debug=True):
        self.__cfg_path = "%s/fdslight_etc/s2hss.ini" % BASE_DIR
        self.__auth_path = "%s/fdslight_etc/access.json" % BASE_DIR
        self.__debug = debug

        self.__listen_fd = -1
        self.__listen_fd6 = -1

        self.create_poll()

        if not debug:
            signal.signal(signal.SIGINT, self.__exit)
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")

        self.create_service()

    @property
    def debug(self):
        return self.__debug

    def release(self):
        if self.__listen_fd > 0:
            self.delete_handler(self.__listen_fd)
        if self.__listen_fd6 > 0:
            self.delete_handler(self.__listen_fd6)

    def __exit(self, signum, frame):
        self.release()

        os.remove(PID_PATH)
        sys.exit(0)

    def create_service(self):
        configs = cfg.ini_parse_from_file(self.__cfg_path)

        listen = configs.get("listen", {})

        enable_ipv6 = bool(int(listen.get("enable_ipv6", 0)))
        listen_ip = listen.get("listen_ip", "0.0.0.0")
        listen_ipv6 = listen.get("listen_ip", "::")
        port = int(listen.get("port", 8900))
        conn_timeout = int(listen.get("conn_timeout", 60))
        heartbeat_timeout = int(listen.get("heartbeat_timeout", 20))

        self.__conn_timeout = conn_timeout
        self.__heartbeat_timeout = heartbeat_timeout
        self.__listen_ip = listen_ip
        self.__listen_ipv6 = listen_ipv6
        self.__enable_ipv6 = enable_ipv6

        self.__listen_fd = self.create_handler(-1, socks2https_server.listener, (listen_ip, port))
        if enable_ipv6:
            self.__listen_fd6 = self.create_handler(-1, socks2https_server.listener, (listen_ipv6, port), is_ipv6=True)

    def get_users(self):
        """获取所有用户的信息
        :return:
        """
        with open(self.__auth_path, "r") as f: s = f.read()
        f.close()

        py_obj = json.loads(s)

        return py_obj

    @property
    def conn_timeout(self):
        return self.__conn_timeout

    @property
    def heartbeat_timeout(self):
        return self.__heartbeat_timeout

    @property
    def listen_ipv6(self):
        return self.__listen_ipv6

    @property
    def listen_ip(self):
        return self.__listen_ip

    @property
    def enable_ipv6(self):
        return self.__enable_ipv6


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    d = None
    if sys.platform.find("win32") > -1:
        is_windows = True
    else:
        is_windows = False

    for k, v in opts:
        if k == "-d": d = v

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    if is_windows and d in ("start", "stop",):
        sys.stderr.write("windows only support -d start argument")
        return

    if d == "stop":
        pid = proc.get_pid(PID_PATH)
        if pid > 0: os.kill(pid, signal.SIGINT)
        return

    debug = True

    if d == "start":
        if os.path.exists(PID_PATH):
            print("the process s2hss exists,please delete %s or kill it at first" % PID_PATH)
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
        cls.ioloop(debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
