#!/usr/bin/env python3

import sys, os, getopt, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfg

import freenet.lib.proc as proc
import freenet.handlers.socks2https_client as socks2https
import freenet.lib.logging as logging

PID_PATH = "/tmp/s2hsc.pid"


def win_client_autocfg():
    """windows自动配置,配置windows能够使用代理
    :return:
    """
    pass


class serverd(dispatcher.dispatcher):
    __cfg_path = None
    __rules_path = None

    __socks5http_listen_fd = None
    __socks5http_listen_fd6 = None

    __relay_listen_fd = None
    __relay_listen_fd6 = None

    __convert_fd = None

    __debug = None

    __configs = None

    __client_conn_timeout = None

    __socks5_bind_ip = None
    __socks5_bind_ipv6 = None

    def init_func(self, mode, debug=True):
        if mode == "proxy":
            self.__cfg_path = "%s/fdslight_etc/s2hsc.ini" % BASE_DIR
        else:
            self.__cfg_path = "%s/fdslight_etc/s2hsr.ini" % BASE_DIR
        self.__rules_path = "%s/fdslight_etc/host_rules.txt" % BASE_DIR
        self.__debug = debug

        self.__socks5http_listen_fd = -1
        self.__socks5http_listen_fd6 = -1

        self.__relay_listen_fd = -1
        self.__relay_listen_fd6 = -1

        self.__convert_fd = -1

        self.create_poll()

        if not debug: signal.signal(signal.SIGINT, self.__exit)

        self.__configs = cfg.ini_parse_from_file(self.__cfg_path)

        if mode == "relay":
            self.create_relay_service()

        if mode == "proxy":
            self.create_socks_http_service()

    def release(self):
        if self.__socks5http_listen_fd > 0:
            self.delete_handler(self.__socks5http_listen_fd)
        if self.__socks5http_listen_fd6 > 0:
            self.delete_handler(self.__socks5http_listen_fd6)
        if self.__relay_listen_fd > 0:
            self.delete_handler(self.__relay_listen_fd)
        if self.__relay_listen_fd6 > 0:
            self.delete_handler(self.__relay_listen_fd6)

    def __exit(self, signum, frame):
        self.release()
        os.remove(PID_PATH)
        sys.exit(0)

    def create_socks_http_service(self):
        config = cfg.ini_parse_from_file(self.__cfg_path)

        c = config.get("socks5_http_listen", {})
        enable_ipv6 = bool(int(c.get("enable_ipv6", 0)))
        listen_ip = c.get("listen_ip", "0.0.0.0")
        listen_ipv6 = c.get("listen_ipv6", "::")
        port = int(c.get("port", 8800))

        self.__socks5_bind_ip = listen_ip
        self.__socks5_bind_ipv6 = listen_ipv6

        if port < 0 or port > 65535:
            raise ValueError("wrong port number from s2hsc.ini")

        conn_timeout = int(c.get("conn_timeout", 60))
        if conn_timeout < 1:
            raise ValueError("wrong conn_timeout value from s2hsc.ini")

        self.__client_conn_timeout = conn_timeout

        self.__socks5http_listen_fd = self.create_handler(
            -1, socks2https.http_socks5_listener, (listen_ip, port), is_ipv6=False
        )
        if enable_ipv6:
            self.__socks5http_listen_fd6 = self.create_handler(
                -1, socks2https.http_socks5_listener, (listen_ipv6, port), is_ipv6=True
            )

    def create_relay_service(self):
        config = cfg.ini_parse_from_file(self.__cfg_path)

    def create_convert_client(self):
        configs = cfg.ini_parse_from_file(self.__cfg_path)

        serv_cfg = configs.get("server_connection", {})
        if not serv_cfg:
            raise SystemError("s2hsc.ini configure file failed")
        enable_ipv6 = bool(int(serv_cfg.get("enable_ipv6", 0)))

        host = serv_cfg.get("host", "")
        port = int(serv_cfg.get("port", 443))
        if port < 0 or port > 65535:
            raise ValueError("wrong port number from s2hsc.ini")

        conn_timeout = int(serv_cfg.get("conn_timeout", 100))

        if conn_timeout < 1:
            raise ValueError("wrong conn_timeout value from s2hsc.ini")

        heartbeat_timeout = int(serv_cfg.get("heartbeat_timeout", 30))

        if heartbeat_timeout < 1:
            raise ValueError("wrong heartbeat_time value from s2hsc.ini")

        path = serv_cfg.get("http_path", "/")
        user = serv_cfg.get("user", "")
        passwd = serv_cfg.get("passwd", "")

        self.__convert_fd = self.create_handler(-1, socks2https.convert_client, (host, port), path, user, passwd,
                                                is_ipv6=enable_ipv6)

    def register_new_conn(self):
        pass

    def get_conn_info(self, packet_id):
        pass

    def send_conn_request(self, frame_type, packet_id, host, port, addr_type, data=b""):
        if self.__convert_fd < 0:
            self.create_convert_client()
        if self.__convert_fd < 0: return

        self.get_handler(self.__convert_fd).send_conn_request(
            frame_type, packet_id, host, port, addr_type, data=data
        )

    def send_tcp_data(self, packet_id, byte_data):
        ### 连接已经断开,那么丢弃tcp数据包
        if self.__convert_fd < 0: return
        self.get_handler(self.__convert_fd).send_tcp_data(packet_id, byte_data)

    @property
    def client_conn_timeout(self):
        return self.__client_conn_timeout

    @property
    def socks5_listen_ip(self):
        return self.__socks5_bind_ip

    @property
    def socks5_listen_ipv6(self):
        return self.__socks5_bind_ipv6


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -m      relay | proxy           relay mode,proxy mode or all mode
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return

    d = None
    m = None

    for k, v in opts:
        if k == "-d": d = v
        if k == "-m": m = v

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    if m not in ("relay", "proxy"):
        print(help_doc)
        return

    if d == "stop":
        pid = proc.get_pid(PID_PATH)
        if pid > 0: os.kill(pid, signal.SIGINT)
        return

    debug = True

    if d == "start":
        if os.path.exists(PID_PATH):
            print("the process s2hsc exists,please delete %s or kill it at first" % PID_PATH)
            return
        debug = False
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)

        proc.write_pid(PID_PATH)

    cls = serverd()
    try:
        cls.ioloop(m, debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
