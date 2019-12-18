#!/usr/bin/env python3
import sys, os, getopt, signal, random

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_PATH = "/tmp/WANd.pid"
LOG_FILE = "%s/WANd.log" % BASE_DIR
ERR_FILE = "%s/WANd_err.log" % BASE_DIR
CFG_FILE = "%s/fdslight_etc/WANd.ini" % BASE_DIR

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg
import freenet.lib.proc as proc
import freenet.lib.cfg_check as cfg_check


class service(dispatcher.dispatcher):
    __debug = None
    __binds = None

    __session_ids = None

    # 控制协议帧连接信息
    __ctl_conns = None

    def init_func(self, debug=False):
        self.__binds = {}
        self.__debug = debug
        self.__session_ids = {}
        self.__ctl_conns = {}

    def __gen_session_id(self):
        session_id = os.urandom(16)
        while session_id in self.__session_ids:
            session_id = os.urandom(16)
        return session_id

    def send_conn_request(self, fd, auth_id, remote_ipaddr, remote_port, is_ipv6=False):
        """向局域网发送请求
        """
        if auth_id not in self.__binds: return None
        if auth_id not in self.__ctl_conns: return None

        session_id = self.__gen_session_id()
        f = self.__ctl_conns[auth_id]

        self.get_handler(f).send_conn_request(session_id, remote_ipaddr, remote_port, is_ipv6=is_ipv6)
        self.__session_ids[session_id] = fd

        return session_id

    def send_conn_data(self, session_id, data):
        pass

    def tell_conn_fail(self, session_id):
        pass

    def tell_conn_ok(self, session_id):
        pass

    def session_del(self, session_id):
        if session_id not in self.__session_ids: return
        del self.__session_ids[session_id]

    def session_get(self, session_id):
        return self.__session_ids.get(session_id, None)

    def __create_service(self, name, configs):
        listen_ip = configs.get("listen_ip", "0.0.0.0")
        if not cfg_check.is_ipv6(listen_ip) or not cfg_check.is_ipv4(listen_ip):
            sys.stderr.write("wrong listen_ip configure from name %s" % name)
            return False

        is_ipv6 = cfg_check.is_ipv6(listen_ip)
        if not cfg_check.is_port(configs.get("port", None)):
            sys.stderr.write("wrong listen port configure from name %s" % name)
            return False

        port = int(configs["port"])

        remote_addr = configs.get("remote_address", "127.0.0.1")
        if not cfg_check.is_ipv6(remote_addr) or not cfg_check.is_ipv4(remote_addr):
            sys.stderr.write("wrong remote_address configure from name %s" % name)
            return False

        remote_is_ipv6 = cfg_check.is_ipv6(remote_addr)
        if not cfg_check.is_port(configs.get("remote_port", None)):
            sys.stderr.write("wrong remote_port configure from name %s" % name)
            return False

        remote_port = int(configs["remote_port"])
        if not cfg_check.is_number(configs.get("heartbeat_time", None)):
            sys.stderr.write("wrong heartbeat_time configure from name %s" % name)
            return False

        timeout = int(configs["timeout"])
        if timeout < 1:
            sys.stderr.write("wrong timeout  configure from name %s" % name)
            return False

        if "auth_id" not in configs:
            sys.stderr.write("not found auth_id configure from name %s" % name)
            return False

        return True

    def create_services(self):
        cfgs = cfg.ini_parse_from_file(CFG_FILE)

        for name in cfgs:
            if name == "listen": continue
            configs = cfgs[name]
            if not self.__create_service(name, configs):
                self.release()
                sys.stderr.write("wrong WANd configure file name:listen")
                return

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
