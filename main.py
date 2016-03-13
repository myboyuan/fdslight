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

FDSL_PID_FILE = "fdslight.pid"

__mode = "client"


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

    def __create_fn_server(self, tunnel):
        if not self.__debug: create_pid_file(FDSL_PID_FILE, os.getpid())

        self.create_poll()
        self.create_handler(-1, tunnel.tunnel, debug=self.__debug)

    def __create_fn_client(self, tunnel):
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

        self.create_handler(-1, tunnel.tunnel, whitelist, blacklist, debug=self.__debug)

    def init_func(self, mode, debug=True):
        if mode == "server":
            t = fns_config.configs["tunnels"]
            name = "freenet.tunnels.%s" % t
        if mode == "client":
            t = fnc_config.configs["tunnelc"]
            name = "freenet.tunnelc.%s" % t
        __import__(name)
        tunnel = sys.modules[name]

        self.__debug = debug

        if debug:
            self.__debug_run(mode, tunnel)
            return

        self.__run(mode, tunnel)

    def __debug_run(self, mode, module):
        if mode == "server": self.__create_fn_server(module)
        if mode == "client": self.__create_fn_client(module)

    def __run(self, mode, module):
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

        if mode == "server":
            self.__create_fn_server(module)
            sys.stdout = open(fns_config.configs["access_log"], "a+")
            sys.stderr = open(fns_config.configs["error_log"], "a+")

        if mode == "client":
            self.__create_fn_client(module)
            sys.stdout = open(fnc_config.configs["access_log"], "a+")
            sys.stderr = open(fnc_config.configs["error_log"], "a+")
            return

        return


def stop_service():
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1: return
    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    -m   client | server
    -d   stop   | start | debug
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
    __mode = m

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
