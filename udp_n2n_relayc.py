#!/usr/bin/env python3
import sys, os, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/udp_n2n_relayc.pid"
LOG_FILE = "/tmp/udp_n2n_relayc.log"
ERR_FILE = "/tmp/udp_n2n_c_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile
import freenet.lib.proc as proc

import freenet.lib.logging as logging
import freenet.handlers.n2n_client as n2n_client


class server(dispatcher.dispatcher):
    __configs = None
    __debug = None

    # 客户端到NAT服务端的映射
    __fwd_tb = None
    # NAT服务端到客户端的映射
    __fwd_tb_reverse = None

    __fds = None

    def init_func(self, debug):
        self.__debug = debug
        self.__fwd_tb = {}
        self.__fwd_tb_reverse = {}

        self.__configs = configfile.ini_parse_from_file("%s/fdslight_etc/udp_n2n_client.ini" % BASE_DIR)
        self.__fds = []

        self.create_poll()
        self.create()

    def create(self):
        for k, v in self.__configs.items():
            host = v["host"]
            port = int(v["port"])
            redir_host = v["redirect_host"]
            redir_port = int(v["redirect_port"])

            fd = self.create_handler(-1, n2n_client.n2nd, ("0.0.0.0", 0), (host, port,), (redir_host, redir_port))
            self.__fds.append(fd)

    def myloop(self):
        pass

    def release(self):
        for fd in self.__fds: self.delete_handler(fd)


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the udp_n2n_relay server process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    cls = server()

    if debug:
        cls.ioloop(debug)
        return
    try:
        cls.ioloop(debug)
    except:
        logging.print_error()
        cls.release()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found udp_n2n_relay client process")
        return

    os.kill(pid, signal.SIGINT)


def __update_user_configs():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found udp_n2n_relay process")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    debug | start | stop    debug,start or stop application
    """

    if len(sys.argv) != 2:
        print(help_doc)
        return

    d = sys.argv[1]

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
    if d == "start": debug = False

    __start_service(debug)


if __name__ == '__main__': main()
