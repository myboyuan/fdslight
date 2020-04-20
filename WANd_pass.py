#!/usr/bin/env python3
import sys, os, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_PATH = "/tmp/WANd.pid"
LOG_FILE = "/tmp/WANd.log"
ERR_FILE = "/tmp/WANd_err.log"
CFG_FILE = "%s/fdslight_etc/WANd.ini" % BASE_DIR
SOCK_FILE = "/tmp/WANd.sock"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg
import freenet.lib.proc as proc
import freenet.lib.cfg_check as cfg_check
import freenet.handlers.WANd_raw as wan_raw
import freenet.handlers.WANd_forward as wan_fwd
import freenet.lib.logging as logging


class service(dispatcher.dispatcher):
    __debug = None
    __binds = None

    __session_ids = None
    __http_upgrade_fd = None

    __fwd_conns = None

    def init_func(self, debug=False):
        self.__binds = {}
        self.__debug = debug
        self.__session_ids = {}
        self.__http_upgrade_fd = -1
        self.__fwd_conns = {}

        self.create_poll()
        self.create_http()
        self.create_services()

    def __gen_session_id(self):
        session_id = os.urandom(16)
        while session_id in self.__session_ids:
            session_id = os.urandom(16)
        return session_id

    def create_http(self):
        self.__http_upgrade_fd = self.create_handler(-1, wan_fwd.listener, SOCK_FILE)

    def send_conn_request(self, fd, auth_id, remote_ipaddr, remote_port, is_ipv6=False):
        """向局域网发送请求
        """
        if self.debug:
            print("send conn request %s" % auth_id)
        if auth_id not in self.__binds: return None
        if auth_id not in self.__fwd_conns: return None

        session_id = self.__gen_session_id()
        f = self.__fwd_conns[auth_id]

        self.get_handler(f).send_conn_request(session_id, remote_ipaddr, remote_port,
                                              is_ipv6=is_ipv6)
        self.__session_ids[session_id] = fd
        return session_id

    def send_data_to_msg_tunnel(self, session_id, data):
        if session_id not in self.__session_ids:
            sys.stderr.write("session id not exists\r\n")
            return
        accepted_fd, msg_tunnel_fd = self.__session_ids[session_id]
        self.send_message_to_handler(accepted_fd, msg_tunnel_fd, data)

    def tell_session_close_from_listener(self, session_id):
        if session_id not in self.__session_ids: return

        accepted_fd, msg_tunnel_fd = self.__session_ids[session_id]
        if msg_tunnel_fd > 0:
            self.delete_handler(msg_tunnel_fd)
        self.delete_handler(accepted_fd)

    def tell_session_fail_from_msg_tunnel(self, session_id):
        if session_id not in self.__session_ids: return
        accepted_fd, msg_tunnel_fd = self.__session_ids[session_id]

        self.delete_handler(accepted_fd)
        self.delete_handler(msg_tunnel_fd)

    def tell_msg_tunnel_conn_ok(self, session_id):
        if session_id not in self.__session_ids: return
        accepted_fd, msg_tunnel_fd = self.__session_ids[session_id]

        self.get_handler(accepted_fd).tell_conn_ok()

    def auth_id_exists(self, auth_id):
        return auth_id in self.__binds

    def reg_fwd_conn(self, auth_id, fd):
        if self.debug:
            print("register connection %s" % auth_id)
        if auth_id in self.__fwd_conns:
            sys.stderr.write("the auth_id exists at self.__fwd_conns\r\n")
            return
        self.__fwd_conns[auth_id] = fd

    def unreg_fwd_conn(self, auth_id):
        if auth_id not in self.__fwd_conns: return
        del self.__fwd_conns[auth_id]

    def session_del(self, session_id):
        if session_id not in self.__session_ids: return
        del self.__session_ids[session_id]

    def session_get(self, session_id):
        return self.__session_ids.get(session_id, None)

    def __create_service(self, name, configs):
        listen_ip = configs.get("listen_ip", "0.0.0.0")
        if not cfg_check.is_ipv6(listen_ip) and not cfg_check.is_ipv4(listen_ip):
            sys.stderr.write("wrong listen_ip configure from name %s\r\n" % name)
            return False

        is_ipv6 = cfg_check.is_ipv6(listen_ip)
        if not cfg_check.is_port(configs.get("port", None)):
            sys.stderr.write("wrong listen port configure from name %s\r\n" % name)
            return False

        port = int(configs["port"])

        remote_addr = configs.get("remote_address", "127.0.0.1")
        if not cfg_check.is_ipv6(remote_addr) and not cfg_check.is_ipv4(remote_addr):
            sys.stderr.write("wrong remote_address configure from name %s\r\n" % name)
            return False

        remote_is_ipv6 = cfg_check.is_ipv6(remote_addr)
        if not cfg_check.is_port(configs.get("remote_port", None)):
            sys.stderr.write("wrong remote_port configure from name %s\r\n" % name)
            return False
        remote_port = int(configs["remote_port"])

        if not cfg_check.is_number(configs.get("timeout", None)):
            sys.stderr.write("wrong timeout configure from name %s\r\n" % name)
            return False

        timeout = int(configs["timeout"])
        if timeout < 1:
            sys.stderr.write("wrong timeout  configure from name %s\r\n" % name)
            return False

        if "auth_id" not in configs:
            sys.stderr.write("not found auth_id configure from name %s\r\n" % name)
            return False
        remote_info = {
            "address": remote_addr,
            "port": remote_port,
            "is_ipv6": remote_is_ipv6,
            "timeout": timeout
        }
        auth_id = configs["auth_id"]
        if auth_id in self.__binds:
            sys.stderr.write("the auth_id %s exists\r\n" % auth_id)
            return False

        fd = self.create_handler(-1, wan_raw.listener, (listen_ip, port,), configs["auth_id"], remote_info,
                                 is_ipv6=is_ipv6)
        if fd < 0:
            sys.stderr.write("create listen %s failed\r\n" % name)
            return False

        self.__binds[auth_id] = fd

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
        if self.__http_upgrade_fd < 0:
            self.delete_handler(self.__http_upgrade_fd)

        for auth_id in self.__binds:
            fd = self.__binds[auth_id]
            self.delete_handler(fd)

    @property
    def debug(self):
        return self.__debug

    def delete_handler(self, fd):
        if fd == self.__http_upgrade_fd:
            self.__http_upgrade_fd = -1
        super().delete_handler(fd)


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
        sys.stderr = open(ERR_FILE, "a")
        sys.stdout = open(LOG_FILE, "a")

    cls = service()
    try:
        cls.ioloop(debug=debug)
    except KeyboardInterrupt:
        cls.release()
        if not debug: os.remove(PID_PATH)
        if os.path.exists(SOCK_FILE): os.remove(SOCK_FILE)
        sys.exit(0)
    except:
        cls.release()
        if not debug: os.remove(PID_PATH)
        if os.path.exists(SOCK_FILE): os.remove(SOCK_FILE)
        logging.print_error()
        sys.exit(-1)


def main():
    help_doc = """
    start | stop | debug
    """
    if len(sys.argv) != 2:
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

    if d == "debug":
        debug = True
    else:
        debug = False

    start(debug)


if __name__ == '__main__': main()
