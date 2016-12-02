#!/usr/bin/env python3

import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.checksum as checksum
import sys, os, signal, socket

pid_dir = "/var/log"
FDSL_PID_FILE = "fdslight.pid"


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


def stop_service():
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1: return
    os.kill(pid, signal.SIGINT)


def update_host_rules():
    """更新黑名单"""
    pid = get_process_id(FDSL_PID_FILE)
    if pid < 1:
        print("cannot found fdslight process")
        return
    os.kill(pid, signal.SIGUSR1)


def clear_pid_file():
    for s in [FDSL_PID_FILE, ]:
        pid_path = "%s/%s" % (pid_dir, s)
        if os.path.isfile(pid_path):
            os.remove(pid_path)
        continue
    return


class fdslight(dispatcher.dispatcher):
    __debug = True
    __raw_socket_fd = -1
    __raw6_socket_fd = -1

    __mode = ""

    __udp_proxy_sessions = {}
    __session_bind = {}

    def __init(self):
        self.create_poll()
        self.__raw_socket_fd = self.create_handler(-1, traffic_pass.traffic_send)
        # elf.__raw6_socket_fd = self.create_handler(-1, traffic_pass.traffic_send, is_ipv6=True)

    @property
    def raw_sock_fd(self):
        return self.__raw_socket_fd

    @property
    def raw6_sock_fd(self):
        return self.__raw6_socket_fd

    @property
    def debug(self):
        return self.__debug

    def init_func(self, debug=True):
        self.__debug = debug
        if debug:
            self.debug_run()
            return

        self.run()

    def debug_run(self):
        self.__init()
        if self.__mode == "server":
            self.create_fn_server()
        if self.__mode == "gateway": self.create_fn_gw()

    def run(self):
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)

        self.__init()
        if self.__mode == "server": self.create_fn_server()
        if self.__mode == "gateway": self.create_fn_gw()

        return

    def __create_udp_proxy(self, session_id, saddr, sport, is_ipv6=False):
        """创建UDP代理,以支持cone nat"""
        if session_id not in self.__udp_proxy_sessions: self.__udp_proxy_sessions[session_id] = {}
        t = self.__udp_proxy_sessions[session_id]
        uniq_id = "%s-%s" % (saddr, sport,)

        if uniq_id in t: return
        raw_sock_fileno = self.__raw_socket_fd
        if is_ipv6: raw_sock_fileno = self.__raw6_socket_fd

        fileno = self.create_handler(-1, traffic_pass.udp_proxy,
                                     raw_sock_fileno, session_id,
                                     saddr, sport, is_ipv6=is_ipv6
                                     )
        t[uniq_id] = fileno

    def del_udp_proxy(self, session_id, saddr, sport):
        """删除UDP proxy"""
        if session_id not in self.__udp_proxy_sessions: return
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return
        del t[uniq_id]
        if not t: del self.__udp_proxy_sessions[session_id]

    def __send_ipv4_msg_to_udp_proxy(self, session_id, message):
        # 检查长度是否合法
        msg_len = len(message)
        if msg_len < 21: return

        ihl = (message[0] & 0x0f) * 4
        pkt_len = (message[2] << 8) | message[3]
        b = ihl + 4
        e = b + 1
        udp_len = (message[b] << 8) | message[e]
        offset = ((message[6] & 0x1f) << 5) | message[7]
        flags = ((message[6]) & 0xe0) >> 5
        df = (flags & 0x2) >> 1
        mf = flags & 0x1

        if df and udp_len >= pkt_len: return
        if udp_len == 0 and offset == 0: return
        if df == 0 and mf == 1 and offset == 0 and udp_len < 512: return

        ihl = (message[0] & 0x0f) * 4
        offset = ((message[6] & 0x1f) << 5) | message[7]

        # 说明不是第一个数据分包,那么就直接发送给raw socket
        if offset:
            L = list(message)
            checksum.modify_address(b"\0\0\0\0", L, checksum.FLAG_MODIFY_SRC_IP)
            self.send_message_to_handler(-1, self.__raw_socket_fd, bytes(L))
            return

        b, e = (ihl, ihl + 1,)
        sport = (message[b] << 8) | message[e]
        saddr = socket.inet_ntoa(message[12:16])

        if not self.__udp_proxy_exists(session_id, saddr, sport):
            self.__create_udp_proxy(session_id, saddr, sport)
        fileno = self.__get_udp_proxy(session_id, saddr, sport)

        self.send_message_to_handler(-1, fileno, message)

    def __send_ipv6_msg_to_udp_proxy(self, session_id, message):
        pass

    def bind_session_id(self, session_id, fileno, other):
        """把session_id和fileno绑定起来"""
        self.__session_bind[session_id] = (fileno, other)

    def unbind_session_id(self, session_id):
        if session_id not in self.__session_bind: return
        del self.__session_bind[session_id]

    def is_bind_session(self, session_id):
        """session是否被绑定"""
        return session_id in self.__session_bind

    def get_bind_session(self, session_id):
        """获取绑定的session的fileno"""
        return self.__session_bind[session_id]

    def send_msg_to_udp_proxy(self, session_id, message):
        """发送消息到UDP PROXY"""
        version = (message[0] & 0xf0) >> 4
        if version not in (4, 6,): return
        if session_id not in self.__session_bind: return
        if version == 4: self.__send_ipv4_msg_to_udp_proxy(session_id, message)
        if version == 6: self.__send_ipv6_msg_to_udp_proxy(session_id, message)

    def __udp_proxy_exists(self, session_id, saddr, sport):
        if session_id not in self.__udp_proxy_sessions: return False
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return False
        return True

    def __get_udp_proxy(self, session_id, saddr, sport):
        if session_id not in self.__udp_proxy_sessions: return None
        uniq_id = "%s-%s" % (saddr, sport,)
        t = self.__udp_proxy_sessions[session_id]
        if uniq_id not in t: return None
        return t[uniq_id]

    def send_msg_to_handler_from_udp_proxy(self, session_id, msg):
        if self.__mode == "gateway":
            ip_ver = msg[0] & 0xf0 >> 4
            raw_fd = self.__raw_socket_fd
            if ip_ver == 6: raw_fd = self.__raw6_socket_fd
            self.send_message_to_handler(-1, raw_fd, msg)
            return
        if session_id not in self.__session_bind: return
        fileno, _ = self.__session_bind[session_id]
        if not self.handler_exists(fileno): return
        self.ctl_handler(-1, fileno, "msg_from_udp_proxy", session_id, msg)

    def set_mode(self, mode):
        if mode not in ("gateway", "server",): raise ValueError("the mode must be client or server")
        self.__mode = mode

    def create_fn_server(self):
        """服务端重写这个方法"""
        pass

    def create_fn_gw(self):
        """网关模式重写这个方法"""
        pass
