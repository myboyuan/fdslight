#!/usr/bin/env python3
import sys, getopt, os, signal

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


class _fdslight_server(dispatcher.dispatcher):
    """网络IO进程
    """
    __configs = None
    __debug = None

    __access = None

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug

    def myloop(self):
        pass

    def handle_msg_from_tunnel(self, session_id, action, message, address):
        pass

    def handle_msg_from_tun(self, message):
        pass

    def response_dns(self, session_id, message):
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
