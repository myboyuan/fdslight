#!/usr/bin/env python3

import sys, os, getopt, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg

import freenet.lib.proc as proc
import freenet.handlers.socks2https_client as socks2http

PID_PATH = "/tmp/s2hsc.pid"


class serverd(dispatcher.dispatcher):
    __cfg_path = None
    __rules_path = None

    __socks5http_listen_fd = None
    __socks5http_listen_fd6 = None

    __relay_listen_fd = None
    __relay_listen_fd6 = None

    __debug = None

    __configs = None

    def init_func(self, mode, debug=True):
        self.__cfg_path = "%s/fdslight_etc/s2hsc.ini" % BASE_DIR
        self.__rules_path = "%s/fdslight_etc/host_rules.txt" % BASE_DIR
        self.__debug = debug

        self.__socks5http_listen_fd = -1
        self.__socks5http_listen_fd6 = -1

        self.__relay_listen_fd = -1
        self.__relay_listen_fd6 = -1

        self.create_poll()

        if not debug: signal.signal(signal.SIGINT, self.__exit)

        self.__configs = cfg.ini_parse_from_file(self.__cfg_path)

        if mode == "relay":
            self.create_relay_service()

        if mode == "proxy":
            self.create_socks_http_service()

    def release(self):
        if self.__socks5http_listen_fd > 0:
            self.delete_handler(self.__socks5http_listen_fd)
        if self.__socks5http_listen_fd6 > 0:
            self.delete_handler(self.__socks5http_listen_fd6)
        if self.__relay_listen_fd > 0:
            self.delete_handler(self.__relay_listen_fd)
        if self.__relay_listen_fd6 > 0:
            self.delete_handler(self.__relay_listen_fd6)

    def __exit(self, signum, frame):
        self.release()
        os.remove(PID_PATH)
        sys.exit(0)

    def create_socks_http_service(self):
        pass

    def create_relay_service(self):
        pass

    def create_convert_client(self):
        pass

    def register_new_conn(self):
        pass

    def get_conn_info(self, packet_id):
        pass


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -m      relay | proxy           relay mode,proxy mode or all mode
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return

    d = None
    m = None

    for k, v in opts:
        if k == "-d": d = v
        if k == "-m": m = v

    if d not in ("debug", "start", "stop"):
        print(help_doc)
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
        cls.ioloop(m, debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
