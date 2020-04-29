#!/usr/bin/env python3
import sys, os, signal, time, getopt

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_PATH = "/tmp/LANd.pid"
LOG_FILE = "/tmp/LANd.log"
ERR_FILE = "/tmp/LANd_err.log"
CFG_FILE = "%s/fdslight_etc/LANd.ini" % BASE_DIR

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg
import freenet.lib.proc as proc
import freenet.lib.cfg_check as cfg_check
import freenet.handlers.LANd_forward as lan_fwd
import freenet.handlers.wol_handler as wol_handler
import freenet.lib.logging as logging


class service(dispatcher.dispatcher):
    __conns = None
    __debug = None
    __sessions = None
    __configs = None
    __time = None

    __wol_fd = None

    def init_func(self, wol_key, wol_port=5888, wol_bind_ip="0.0.0.0", debug=False):
        self.__wol_fd = -1
        self.__debug = debug
        self.__sessions = {}
        self.__configs = {}
        self.__conns = {}
        self.__time = time.time()
        self.__debug = debug

        if not cfg_check.is_port(wol_port):
            sys.stderr.write("wrong wol port number %s\r\n")
            return

        self.create_poll()
        self.create_wol(wol_key, wol_port, wol_bind_ip)
        self.create_connections()

    def create_wol(self, wol_key, wol_port, wol_bind_ip):
        self.__wol_fd = self.create_handler(
            -1, wol_handler.listener, ("127.0.0.1", wol_port), wol_bind_ip, wol_key
        )

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
        if not cfg_check.is_ipv4(host) and not cfg_check.is_ipv6(host): is_ipv6 = force_ipv6
        if cfg_check.is_ipv6(host): is_ipv6 = True

        if not cfg_check.is_port(configs.get("port", "443")):
            sys.stderr.write("wrong port value from configure %s\r\n" % name)
            return False

        port = int(configs.get("port", "443"))
        auth_id = configs["auth_id"]
        uri = configs["URI"]

        if auth_id in self.__conns:
            sys.stderr.write("auth id %s exists\r\n" % auth_id)
            return False

        fd = self.create_handler(-1, lan_fwd.client, (host, port,), uri, auth_id, is_ipv6=is_ipv6)
        if fd < 0:
            sys.stderr.write("create %s connection is failed\r\n" % name)
            return False

        self.__conns[auth_id] = fd
        return True

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
        seq = []
        for session_id in self.__sessions:
            seq.append(self.__sessions[session_id])

        for fd in seq:
            self.delete_handler(fd)

        seq = []

        for auth_id in self.__conns:
            fd = self.__conns[auth_id]
            seq.append(fd)

        for fd in seq:
            self.delete_handler(fd)

        if self.__wol_fd > 0:
            self.delete_handler(self.__wol_fd)

    @property
    def debug(self):
        return self.__debug

    def delete_fwd_conn(self, auth_id):
        if auth_id not in self.__conns: return
        del self.__conns[auth_id]

    def handle_conn_request(self, address, path, auth_id, session_id, remote_addr, remote_port, is_ipv6):
        if session_id in self.__sessions:
            fd = self.__sessions[session_id]
            logging.print_general("delete %s,%s" % (auth_id, session_id,), (remote_addr, remote_port,))
            self.delete_handler(fd)
            del self.__sessions[session_id]

        fd = self.create_handler(-1, lan_fwd.client, address, path, auth_id, session_id=session_id,
                                 is_msg_tunnel=True, is_ipv6=is_ipv6)

        self.get_handler(fd).set_forwarding_addr((remote_addr, remote_port,), is_ipv6=is_ipv6)
        self.__sessions[session_id] = fd

    def myloop(self):
        """检查哪些连接已经丢失,对于连接失败的重新建立连接
        """
        # 每隔一段时间重新建立连接
        t = time.time()
        if t - self.__time < 10: return
        self.__time = time.time()

        names = []

        for name in self.__configs:
            config = self.__configs[name]
            auth_id = config["auth_id"]
            if auth_id not in self.__conns: names.append((name, config,))
        ''''''

        for name, config in names:
            self.__create_conn(name, config)


def update_configs():
    pid = proc.get_pid(PID_PATH)
    if pid < 0:
        sys.stderr.write("not found process\r\n")
        sys.stderr.flush()
        return
    os.kill(pid, signal.SIGUSR1)


def start(debug, wol_key, wol_port, wol_bind_ip):
    if not debug:
        if os.path.exists(PID_PATH):
            sys.stderr.write("the process exists\r\n")
            sys.exit(-1)
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)

        sys.stderr = open(ERR_FILE, "a")
        sys.stdout = open(LOG_FILE, "a")

        proc.write_pid(PID_PATH)
    cls = service()
    try:
        cls.ioloop(wol_key, wol_bind_ip=wol_bind_ip, debug=debug, wol_port=wol_port)
    except KeyboardInterrupt:
        if os.path.exists(PID_PATH): os.remove(PID_PATH)
        cls.release()
        sys.exit(0)
    except:
        if os.path.exists(PID_PATH): os.remove(PID_PATH)
        cls.release()
        logging.print_error()
        sys.exit(-1)


def main():
    help_doc = """
    start | stop | debug
    start | debug  --wol_listen_port=port --wol_key=key --wol_bind_ip=ip
    """
    if len(sys.argv) < 2:
        print(help_doc)
        return

    if sys.argv[1] not in ("start", "stop", "debug",):
        print(help_doc)
        return

    d = sys.argv[1]

    if d == "stop":
        pid = proc.get_pid(PID_PATH)
        if pid > 0: os.kill(pid, signal.SIGINT)
        return

    try:
        opts, args = getopt.getopt(sys.argv[2:], "", ["wol_listen_port=", "wol_key=", "wol_bind_ip="])
    except getopt.GetoptError:
        print(help_doc)
        return
    except IndexError:
        print(help_doc)
        return

    wol_port = 5888
    wol_key = None
    wol_bind_ip = None

    for k, v in opts:
        if k == "--wol_listen_port":
            if not cfg_check.is_port(v):
                sys.stderr.write("wrong port number\r\n")
                return
            wol_port = int(v)
        if k == "--wol_key": wol_key = v
        if k == "--wol_bind_ip": wol_bind_ip = v
        ''''''
    if not wol_key:
        sys.stderr.write("please set wol key\r\n")
        return
    if not wol_bind_ip:
        sys.stderr.write("please set wol bind ip")
        return

    if d == "debug":
        debug = True
    else:
        debug = False

    start(debug, wol_key, wol_port, wol_bind_ip)


if __name__ == '__main__': main()
