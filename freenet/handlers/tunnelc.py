#!/usr/bin/env python3
"""客户端隧道实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time
import freenet.lib.utils as proto_utils


class tunnel_tcp(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0
    __sent_queue = None

    def init_func(self, creator, crypto, crypto_configs, conn_timeout=720, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_STREAM)

        self.set_socket(s)
        self.__conn_timeout = conn_timeout
        self.__sent_queue = []

        return self.fileno

    def create_tunnel(self, server_address):
        try:
            self.connect(server_address)
        except socket.gaierror:
            return False

        return True

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__decrypt.input(rdata)

        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except proto_utils.ProtoError:
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.__decrypt.get_pkt()
                if not pkt_info: break
                self.dispatcher.handle_msg_from_tunnel(*pkt_info)
            ''''''
            self.__update_time = time.time()
        return

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_tunnel_close()
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

        t = time.time()

        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def connect_ok(self):
        self.__update_time = time.time()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        # 发送还没有连接的时候堆积的数据包
        if not self.__sent_queue: self.add_evt_write(self.fileno)
        while 1:
            try:
                sent_pkt = self.__sent_queue.pop(0)
            except IndexError:
                break
            self.writer.write(sent_pkt)
        return

    def send_msg_to_tunnel(self, session_id, action, message):
        sent_pkt = self.__encrypt.build_packet(session_id, action, message)

        if not self.is_conn_ok():
            self.__sent_queue.append(sent_pkt)
        else:
            self.__update_time = time.time()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)


class udp_tunnel(udp_handler.udp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0
    __sent_queue = None

    def init_func(self, creator, crypto, crypto_configs, conn_timeout=720, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.__conn_timeout = conn_timeout
        self.__sent_queue = []

        return self.fileno

    def create_tunnel(self, server_address):
        try:
            self.connect_ex(server_address)
        except socket.gaierror:
            return False

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__update_time = time.time()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return True

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result
        self.dispatcher.handle_msg_from_tunnel(session_id, action, byte_data)
        self.__update_time = time.time()

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.dispatcher.tell_tunnel_close()
        self.close()

    def send_msg_to_tunnel(self, session_id, action, message):
        try:
            ippkts = self.__encrypt.build_packets(session_id, action, message)
            self.__encrypt.reset()
        except ValueError:
            return

        for ippkt in ippkts: self.send(ippkt)

        self.add_evt_write(self.fileno)
        self.__update_time = time.time()
