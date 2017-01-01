#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import socket, time, sys
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.lib.base_proto.utils as proto_utils


class tunnel_tcp_listener(tcp_handler.tcp_handler):
    __debug = None
    __module = None
    __tun_fd = -1
    __tun6_fd = -1

    __dns_fd = None

    # 最大连接数
    __max_conns = 10
    # 当前连接数
    __curr_conns = 0

    __auth_module = None

    def init_func(self, creator_fd, tun_fd, tun6_fd, dns_fd, auth_module, debug=True, is_ipv6=False):
        self.__debug = debug
        self.__max_conns = fns_config.configs["max_tcp_conns"]

        self.__tun_fd = tun_fd
        self.__tun6_fd = tun6_fd

        self.__dns_fd = dns_fd

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            bind = fns_config.configs["tcp6_listen"]
        else:
            s = socket.socket()
            bind = fns_config.configs["tcp_listen"]

        self.__auth_module = auth_module
        self.set_socket(s)
        self.bind(bind)

        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            if self.__curr_conns == self.__max_conns:
                cs.close()
                return
            self.__curr_conns += 1
            self.create_handler(self.fileno, tunnels_tcp_handler,
                                self.__tun_fd, self.__tun6_fd, self.__dns_fd,
                                cs, caddr, self.__auth_module, debug=self.__debug
                                )
            ''''''
        return

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("del_conn",): return None
        if cmd == "del_conn": self.__curr_conns -= 1

        return None


class tunnels_tcp_handler(tcp_handler.tcp_handler):
    __debug = None
    __caddr = None
    __LOOP_TIMEOUT = 10

    # 连接超时
    __conn_timeout = 1200
    __conn_time = 0

    __encrypt = None
    __decrypt = None

    __creator_fd = None

    __tun_fd = -1
    __tun6_fd = -1
    __dns_fd = -1

    __BUFSIZE = 16 * 1024
    __session_id = None

    __auth_module = None

    def init_func(self, creator_fd, tun_fd, tun6_fd, dns_fd, cs, caddr, auth_module, debug=True):
        self.__debug = debug
        self.__caddr = caddr
        self.__auth_module = auth_module

        self.__conn_timeout = int(fns_config.configs["timeout"])

        name = "freenet.lib.crypto.%s" % fns_config.configs["tcp_crypto_module"]["name"]
        __import__(name)

        crypto = sys.modules[name]

        crypto_config = fns_config.configs["tcp_crypto_module"]["configs"]

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_config)
        self.__decrypt.config(crypto_config)

        self.__creator_fd = creator_fd
        self.__tun_fd = tun_fd
        self.__tun6_fd = tun6_fd
        self.__dns_fd = dns_fd

        self.__conn_time = time.time()

        self.set_socket(cs)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.print_access_log("connect")

        return self.fileno

    def __send_data(self, byte_data, action=tunnel_tcp.ACT_DATA):
        # 清空还没有发送的数据
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        if not self.__auth_module.handle_send(self.__session_id, len(byte_data)): return

        self.__conn_time = time.time()
        sent_data = self.encrypt.build_packet(self.__session_id, action, byte_data)
        self.writer.write(sent_data)
        self.add_evt_write(self.fileno)
        self.encrypt.reset()

    def __handle_ipv4_data_from_tunnel(self, byte_data):
        if not self.dispatcher.check_ipv4_data(byte_data):
            self.print_access_log("wrong_ip_packet")
            self.delete_handler(self.fileno)
            return

        protocol = byte_data[9]

        if protocol not in (1, 6, 17,): return
        if protocol == socket.IPPROTO_UDP:
            self.dispatcher.send_msg_to_udp_proxy(self.__session_id, byte_data)
            return

        self.ctl_handler(self.fileno, self.__tun_fd, "set_packet_session_id", self.__session_id)
        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self):
        pass

    def __handle_data_from_tunnel(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        self.__conn_time = time.time()

        if ip_ver == 4: self.__handle_ipv4_data_from_tunnel(byte_data)
        if ip_ver == 6: self.__handle_ipv6_data_from_tunnel(byte_data)

    def __handle_dns_request(self, dns_msg):
        self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", self.__session_id, dns_msg)

    def __handle_read(self, session_id, action, byte_data):
        if action not in tunnel_tcp.ACTS:
            self.print_access_log("not_support_action_type")
            return
        # 对session的处理
        if not self.__session_id: self.__session_id = session_id
        if session_id != self.__session_id: return

        if not self.__auth_module.handle_recv(self.__session_id, len(byte_data)):
            self.print_access_log("auth_forbid_recv")
            self.delete_handler(self.fileno)
            return

        if self.dispatcher.is_bind_session(session_id):
            # 如果之前绑定了会话,那么删除之前的连接
            fileno, other = self.dispatcher.get_bind_session(session_id)
            if other != "udp" and fileno != self.fileno: self.delete_handler(fileno)
        self.dispatcher.bind_session_id(session_id, self.fileno, "tcp")

        if action == tunnel_tcp.ACT_DNS: self.__handle_dns_request(byte_data)
        if action == tunnel_tcp.ACT_DATA: self.__handle_data_from_tunnel(byte_data)

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__decrypt.input(rdata)

        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except proto_utils.ProtoError:
                self.print_access_log("wrong_format_packet")
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.decrypt.get_pkt()
                if not pkt_info: break
                self.__handle_read(*pkt_info)
            ''''''
        return

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.print_access_log("error")
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__conn_time > self.__conn_timeout:
            self.print_access_log("timeout")
            self.delete_handler(self.fileno)
            return
        self.__auth_module.handle_timing_task(self.__session_id)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        if self.__session_id:
            self.dispatcher.unbind_session_id(self.__session_id)
        self.print_access_log("conn_close")
        self.unregister(self.fileno)
        self.close()
        self.__auth_module.handle_close(self.__session_id)
        self.ctl_handler(self.fileno, self.__creator_fd, "del_conn")

    def message_from_handler(self, from_fd, byte_data):
        self.__send_data(byte_data, action=tunnel_tcp.ACT_DATA)

    def __send_dns(self, byte_data):
        if self.__debug: self.print_access_log("send_dns")
        self.__send_data(byte_data, action=tunnel_tcp.ACT_DNS)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("response_dns", "msg_from_udp_proxy", "set_packet_session_id",): return False
        if cmd == "response_dns":
            session_id, dns_msg, = args
            self.__send_dns(dns_msg)
            return
        if cmd == "set_packet_session_id": return

        session_id, msg = args
        self.__send_data(msg)

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__caddr
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()
