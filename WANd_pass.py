#!/usr/bin/env python3
import sys, os, getopt, signal, random

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_PATH = "/tmp/WANd.pid"
LOG_FILE = "%s/WANd.log" % BASE_DIR
ERR_FILE = "%s/WANd_err.log" % BASE_DIR

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg
import freenet.lib.proc as proc
import freenet.lib.cfg_check as cfg_check


class service(dispatcher.dispatcher):
    __binds = None
    __debug = None

    def init_func(self, debug=False):
        self.__binds = {}
        self.__debug = debug

    def register_bind(self, fd, name):
        pass

    def unregiser_bind(self, name):
        pass

    def create_services(self):
        pass

    def release(self):
        pass

    @property
    def debug(self):
        return self.__debug


def update_configs():
    pid = proc.get_pid(PID_PATH)
    if pid < 0:
        sys.stderr.write("not found process\r\n")
        sys.stderr.flush()
        return
    os.kill(pid, signal.SIGUSR1)


def start(debug):
    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)

        proc.write_pid(PID_PATH)

    cls = service()
    try:
        cls.ioloop(debug=debug)
    except KeyboardInterrupt:
        cls.release()
        sys.exit(0)


def main():
    help_doc = """
    start | stop | debug | reload
    """
    if len(sys.argv) != 2:
        print(help_doc)
        return

    if sys.argv[1] not in ("start", "stop", "debug", "reload",):
        print(help_doc)
        return

    d = sys.argv[1]

    if d == "stop":
        pid = proc.get_pid(PID_PATH)
        if pid > 0: os.kill(pid, signal.SIGINT)
        return

    if d == "debug":
        debug = True
    else:
        debug = False

    start(debug)


if __name__ == '__main__': main()
