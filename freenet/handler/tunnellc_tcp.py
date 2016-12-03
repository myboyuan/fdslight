#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import fdslight_etc.fn_local as fnlc_config
import socket, sys
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp


class tunnellc_tcp(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None
    __session_id = None

    __LOOP_TIMEOUT = 10

    __wait_sent = None

    def init_func(self, creator, session_id, is_ipv6=False):
        address = fnlc_config.configs["tcp_server_address"]

        name = "freenet.lib.crypto.%s" % fnlc_config.configs["tcp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_config = fnlc_config.configs["tcp_crypto_module"]["configs"]

        self.__encrypt = m.encrypt()
        self.__decrypt = m.decrypt()

        self.__encrypt.config(crypto_config)
        self.__decrypt.config(crypto_config)

        self.__session_id = session_id
        self.__wait_sent = []

        # 如果是域名,那么获取真是IP地址,防止死循环查询
        ipaddr = self.dispatcher.get_ipaddr(address[0])
        address = (ipaddr, address[1],)

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket()

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.dispatcher.tunnel_ok()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        while 1:
            try:
                is_dns, byte_data = self.__wait_sent.pop(0)
            except IndexError:
                break
            if is_dns:
                self.__send_data(byte_data, action=tunnel_tcp.ACT_DNS)
            else:
                self.__send_data(byte_data)

    def __handle_data_from_tunnel(self, session_id, action, byte_data):
        if action not in tunnel_tcp.ACTS: return
        if session_id != self.__session_id: return

        if action == tunnel_tcp.ACT_DNS:
            dns_fd = self.dispatcher.get_dns()
            self.ctl_handler(self.fileno, dns_fd, byte_data)
            return
        ip_ver = (byte_data[0] & 0xf0) >> 4
        # 暂时不支持ipv6
        if ip_ver != 6: return
        tun_fd = self.dispatcher.get_tun()
        self.send_message_to_handler(self.fileno, tun_fd, byte_data)

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__decrypt.input(rdata)
        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except tunnel_tcp.ProtoError:
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.decrypt.get_pkt()
                if not pkt_info: break
                self.__handle_data_from_tunnel(*pkt_info)
            ''''''
        return

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
        self.dispatcher.tunnel_fail()

    def __send_data(self, sent_data, action=tunnel_tcp.ACT_DATA):
        sent_pkt = self.__encrypt.build_packet(self.__session_id, action, sent_data)
        # 丢弃阻塞的包
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        self.__encrypt.reset()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)

    def __handle_data_from_tun(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        self.__send_data(byte_data)

    def message_from_handler(self, from_fd, byte_data):
        if not self.dispatcher.tunnel_is_ok():
            self.__wait_sent.append((0, byte_data))
            return
        self.__handle_data_from_tun(byte_data)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "request_dns": return
        message, = args
        if not self.dispatcher.tunnel_is_ok():
            self.__wait_sent.append((1, message))
            return
        self.__send_data(message, action=tunnel_tcp.ACT_DNS)
