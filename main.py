#!/usr/bin/env python3
import signal, sys, os, getopt

d = os.path.dirname(sys.argv[0])
sys.path.append(d)
pid_dir = "/tmp"

import pywind.evtframework.evt_dispatcher as dispatcher
import freeroute.handler.dnsd_proxy as dnsd_proxy
import fdslight_etc.fn_server as fns_config
import fdslight_etc.fn_client as fnc_config

FDSL_PID_FILE = "fdslight.pid"


def create_pid_file(fname, pid):
    pid_path = "%s/%s" % (pid_dir, fname)
    fd = open(pid_path, "w")
    fd.write(str(pid))
    fd.close()


def get_process_pid(fname):
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
    __dns_config = None
    __fn_config = None

    def __create_fn_tcp_server(self, tunnels):
        fn_s_no = self.create_handler(-1, tunnels.tcp_tunnel)
        self.get_handler(fn_s_no).after()

    def __create_fn_tcp_client(self, tunnelc):
        self.create_handler(-1, tunnelc.tcp_tunnel)

    def __create_fn_dns_proxy(self, debug=False):
        self.create_handler(-1, dnsd_proxy.dnsd_proxy, debug=debug)

    def init_func(self, mode, debug=True):
        if mode == "server":
            t = fns_config.configs["tunnels"]
            name = "freenet.tunnels.%s" % t
        if mode == "client":
            t = fnc_config.configs["tunnelc"]
            name = "freenet.tunnelc.%s" % t

        __import__(name)
        tunnel = sys.modules[name]

        if debug:
            self.__debug_run(mode, tunnel)
            return

        self.__run(mode, tunnel)

    def init_func_after_fork(self):
        self.create_poll()

    def __debug_run(self, mode, module):
        self.create_poll()
        if mode == "server":
            self.__create_fn_tcp_server(module)
        if mode == "client":
            self.__create_fn_tcp_client(module)
            self.__create_fn_dns_proxy(debug=True)
        return

    def __run(self, mode, module):
        pid = os.fork()
        if pid != 0:
            sys.exit(0)

        os.setsid()
        os.chdir("/")
        os.umask(0)
        pid = os.fork()
        if pid != 0:
            sys.exit(0)

        if mode == "server":
            sys.stdout = open(fns_config.configs["access_log"], "a+")
            sys.stderr = open(fns_config.configs["error_log"], "a+")
            create_pid_file(FDSL_PID_FILE, os.getpid())
            self.init_func_after_fork()
            self.__create_fn_tcp_server(module)

        if mode == "client":
            sys.stdout = open("/dev/null", "w")
            sys.stderr = open("/dev/null", "w")
            create_pid_file(FDSL_PID_FILE, os.getpid())
            self.init_func_after_fork()

            self.__create_fn_tcp_client(module)
            self.__create_fn_dns_proxy()
            return

        return


def stop_service():
    pid = get_process_pid(FDSL_PID_FILE)
    if pid < 1:
        return

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
    if d == "debug":
        debug = True

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
