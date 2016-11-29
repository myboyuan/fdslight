#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import socket, time, sys
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.lib.base_proto.utils as proto_utils


class _tunnel_tcp_listen(tcp_handler.tcp_handler):
    __debug = None
    __module = None
    __tun_fd = -1
    __dns_fd = None

    __dns_fd = None
    __nat = None

    # 最大连接数
    __max_conns = 10
    # 当前连接数
    __curr_conns = 0

    def init_func(self, creator_fd, tun_fd, dns_fd, nat, debug=True):
        self.__debug = debug
        self.__max_conns = fns_config.configs["max_tcp_conns"]

        name = "freenet.tunnels.%s" % fns_config.configs["tcp_tunnel"]
        __import__(name)
        self.__module = sys.modules[name]
        self.__nat = nat

        self.__tun_fd = tun_fd
        self.__dns_fd = dns_fd

        s = socket.socket()
        self.set_socket(s)
        self.bind(fns_config.configs["tcp_listen"])

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
            self.create_handler(self.fileno, self.__module.tunnel,
                                self.__tun_fd,
                                cs, caddr, self.__nat,
                                debug=self.__debug
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
        if cmd not in ("request_dns", "response_dns", "del_conn",): return None
        if cmd == "del_conn": self.__curr_conns -= 1
        if cmd == "request_dns":
            dns_msg, = args
            self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", from_fd, dns_msg)
        if cmd == "response_dns":
            t_fd, resp_dns_msg, = args
            if not self.handler_exists(t_fd): return None
            self.ctl_handler(self.fileno, t_fd, "response_dns", resp_dns_msg)

        return None


class tunnels_tcp_base(tcp_handler.tcp_handler):
    __debug = None
    __caddr = None
    __LOOP_TIMEOUT = 10

    # 连接超时
    __conn_timeout = 1200
    __conn_time = 0

    __encrypt = None
    __decrypt = None

    __creator_fd = None

    __traffic_send_fd = -1
    __tun_fd = -1
    __BUFSIZE = 16 * 1024
    __session_id = None

    __nat = None

    def init_func(self, creator_fd, tun_fd, cs, caddr, nat, debug=True):
        self.__debug = debug
        self.__caddr = caddr

        name = "freenet.lib.crypto.%s" % fns_config.configs["tcp_crypto_module"]["name"]
        __import__(name)

        crypto = sys.modules[name]

        args = fns_config.configs["tcp_crypto_module"]["args"]

        self.__encrypt = crypto.encrypt(*args)
        self.__decrypt = crypto.decrypt(*args)
        self.__creator_fd = creator_fd
        self.__tun_fd = tun_fd
        self.__nat = nat
        self.__conn_time = time.time()

        self.fn_init()

        self.set_socket(cs)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.print_access_log("connect")

        return self.fileno

    def __send_data(self, byte_data, action=tunnel_tcp.ACT_DATA):
        # 清空还没有发送的数据
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        if action == tunnel_tcp.ACT_DATA:
            if not self.fn_send(self.__session_id, len(byte_data)):
                self.delete_handler(self.fileno)
                return
            ''''''
        self.__conn_time = time.time()
        sent_data = self.encrypt.build_packet(self.__session_id, action, byte_data)
        self.writer.write(sent_data)
        self.add_evt_write(self.fileno)
        self.encrypt.reset()

    def __handle_ipv4_data_from_tunnel(self, byte_data):
        pkt_len = (byte_data[2] << 8) | byte_data[3]
        if len(byte_data) != pkt_len:
            self.print_access_log("error_pkt_length:real:%s,protocol:%s" % (len(byte_data), pkt_len,))
            self.delete_handler(self.fileno)
            return
        if not self.fn_recv(self.__session_id, pkt_len):
            self.delete_handler(self.fileno)
            return
        protocol = byte_data[9]

        if protocol not in (1, 6, 17,): return
        if protocol == socket.IPPROTO_UDP:
            self.dispatcher.send_msg_to_udp_proxy(self.__session_id, byte_data)
            return

        msg = self.__nat.get_ippkt2sLan_from_cLan(self.__session_id, byte_data)
        self.send_message_to_handler(self.fileno, self.__tun_fd, msg)

    def __handle_ipv6_data_from_tunnel(self):
        pass

    def __handle_data_from_tunnel(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        self.__conn_time = time.time()

        if ip_ver == 4: self.__handle_ipv4_data_from_tunnel(byte_data)
        if ip_ver == 6: self.__handle_ipv6_data_from_tunnel(byte_data)

    def __handle_dns_request(self, dns_msg):
        self.ctl_handler(self.fileno, self.__creator_fd, "request_dns", dns_msg)

    def __handle_read(self, session_id, action, byte_data):
        if action not in tunnel_tcp.ACTS:
            self.print_access_log("not_support_action_type")
            return

        # 对session的处理
        if not self.__session_id: self.__session_id = session_id
        if session_id != self.__session_id: return
        self.dispatcher.bind_session_id(session_id, self.fileno)

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
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        self.__nat.recycle()
        t = time.time()
        if t - self.__conn_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.fn_timeout(self.__session_id)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        if self.__session_id:
            self.dispatcher.unbind_session_id(self.__session_id)
        self.print_access_log("conn_close")
        self.unregister(self.fileno)
        self.close()
        self.fn_close(self.__session_id)
        self.ctl_handler(self.fileno, self.__creator_fd, "del_conn")

    def message_from_handler(self, from_fd, byte_data):
        rs = self.__nat.get_ippkt2cLan_from_sLan(byte_data)
        if not rs: return

        session_id, msg = rs
        self.__send_data(msg, action=tunnel_tcp.ACT_DATA)

    def fn_init(self):
        """重写这个方法"""
        pass

    def fn_recv(self, session_id, pkt_len):
        """处理接收
        ：:return Boolean, True表示继续,False表示不继续执行
        """
        return True

    def fn_send(self, session_id, pkt_len):
        """处理发送
        :return Boolean,True表示继续,False表示不继续执行
        """
        return True

    def fn_close(self, session_id):
        """处理连接关闭
        :return:
        """
        return

    def fn_timeout(self, session_id):
        """用来处理定时任务"""
        pass

    def __send_dns(self, byte_data):
        if self.__debug: self.print_access_log("send_dns")
        self.__send_data(byte_data, action=tunnel_tcp.ACT_DNS)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("response_dns", "msg_from_udp_proxy",): return False
        if cmd == "response_dns":
            dns_msg, = args
            self.__send_dns(dns_msg)
            return
        session_id, msg = args
        self.__send_data(msg)

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__caddr
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()
