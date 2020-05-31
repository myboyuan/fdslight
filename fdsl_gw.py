#!/usr/bin/env python3
import sys, os, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/fdsl_gw.pid"
LOG_FILE = "/tmp/fdsl_gw.log"
ERR_FILE = "/tmp/fdsl_gw_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile

import freenet.lib.logging as logging
import freenet.lib.proc as proc
import freenet.lib.gw as gw


class fdsl_gw(dispatcher.dispatcher):
    __configs = None
    __debug = None
    __gw = None

    def init_func(self, debug, configs):
        # netmap 只能使用select事件监听
        self.create_poll(force_select=True)

    @property
    def debug(self):
        return self.__debug

    @property
    def configs(self):
        return self.__configs

    @property
    def gw(self):
        return self.__gw

    def myloop(self):
        pass


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the fdsl_gw process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    configs = configfile.ini_parse_from_file("%s/fdslight_etc/fn_gw.ini" % BASE_DIR)
    cls = fdsl_gw()

    if debug:
        cls.ioloop(debug, configs)
        return
    try:
        cls.ioloop(debug, configs)
    except:
        logging.print_error()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found fdslight gateway process")
        return

    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    debug | start | stop    debug,start or stop application
    """

    if len(sys.argv) != 2:
        print(help_doc)
        return

    d = sys.argv[1]

    if d not in ("debug", "start", "stop",):
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
