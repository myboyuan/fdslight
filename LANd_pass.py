#!/usr/bin/env python3
import sys, os, getopt, signal, random

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_PATH = "/tmp/LANd.pid"
LOG_FILE = "%s/LANd.log" % BASE_DIR
ERR_FILE = "%s/LANd_err.log" % BASE_DIR
CFG_FILE = "%s/fdslight_etc/LANd.ini" % BASE_DIR

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg
import freenet.lib.proc as proc
import freenet.lib.cfg_check as cfg_check
import freenet.handlers.LANd_forward as lan_fwd
import freenet.handlers.LANd_raw as lan_raw


class service(dispatcher.dispatcher):
    __conns = None
    __debug = None
    __sessions = None
    __configs = None

    def init_func(self, debug=False):
        self.__debug = debug
        self.__sessions = {}
        self.__configs = {}

    def __create_conn(self, name, configs):
        if "host" not in configs:
            sys.stderr.write("not found host from configure %s\r\n" % name)
            return False
        if "auth_id" not in configs:
            sys.stderr.write("not found auth_id from configure %s\r\n" % name)
            return False
        if "URI" not in configs:
            sys.stderr.write("not found URI from configure %s\r\n" % name)
            return False

        if not cfg_check.is_number(configs.get("force_ipv6", "0")):
            sys.stderr.write("wrong force_ipv6 value from configure %s\r\n" % name)
            return False

        force_ipv6 = bool(int(configs.get("force_ipv6", "0")))
        host = configs["host"]
        is_ipv6 = False
        if not cfg_check.is_ipv4(host) and not cfg_check.is_ipv6(host): is_ipv6 = True
        if cfg_check.is_ipv6(host): is_ipv6 = True

        if not cfg_check.is_port(configs.get("port", "443")):
            sys.stderr.write("wrong port value from configure %s\r\n" % name)
            return False

        port = int(configs.get("port", "443"))
        auth_id = configs["auth_id"]
        uri = configs["uri"]

        if auth_id in self.__conns:
            sys.stderr.write("auth id %s exists\r\n" % auth_id)
            return False

        fd = self.create_handler(-1, lan_fwd.client, (host, port,), uri, auth_id, is_ipv6=is_ipv6, ssl_on=True)
        if fd < 0:
            sys.stderr.write("create %s connection is failed\r\n" % name)
            return False

        self.__conns[auth_id] = fd

    def create_connections(self):
        cfgs = cfg.ini_parse_from_file(CFG_FILE)

        for name in cfgs:
            rs = self.__create_conn(name, cfgs[name])
            if not rs:
                self.release()
                break
            ''''''
        self.__configs = cfgs

    def release(self):
        pass

    @property
    def debug(self):
        return self.__debug

    def session_del(self, session_id):
        if session_id not in self.__sessions: return
        del self.__sessions[session_id]

    def session_get(self, session_id):
        return self.__sessions.get(session_id, None)

    def send_conn_data_to_local(self, session_id, byte_data):
        if session_id not in self.__sessions: return
        fd = self.__sessions[session_id]
        self.send_message_to_handler(-1, fd, byte_data)

    def send_conn_data_to_server(self, auth_id, session_id, byte_data):
        if auth_id not in self.__conns: return
        fd = self.__conns[auth_id]
        self.get_handler(fd).send_conn_data(session_id, byte_data)

    def send_conn_fail(self, auth_id, session_id):
        if auth_id not in self.__conns: return
        fd = self.__conns[auth_id]
        self.get_handler(fd).send_conn_fail(session_id)

    def send_conn_ok(self, auth_id, session_id):
        if auth_id not in self.__conns: return
        fd = self.__conns[auth_id]
        self.get_handler(fd).send_conn_ok(session_id)

    def send_conn_close(self, auth_id, session_id):
        if auth_id not in self.__conns: return
        fd = self.__conns[auth_id]
        self.get_handler(fd).send_conn_close(session_id)

    def handle_conn_request(self, auth_id, session_id, remote_addr, remote_port, is_ipv6):
        if session_id in self.__sessions:
            self.tell_delete(session_id)

        fd = self.create_handler(-1, lan_raw.client, (remote_addr, remote_port,), auth_id, session_id, is_ipv6=is_ipv6)
        self.__sessions[session_id] = fd

    def myloop(self):
        """检查哪些连接已经丢失,对于连接失败的重新建立连接
        """
        for name in self.__configs:
            config = self.__configs[name]
            auth_id = config["auth_id"]
            if auth_id not in self.__conns:
                rs = self.__create_conn(name, config)
                if not rs: continue
            ''''''
        ''''''


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
        cls.ioloop()
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
