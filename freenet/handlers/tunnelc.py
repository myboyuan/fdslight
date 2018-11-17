#!/usr/bin/env python3
"""客户端隧道实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.logging as logging


class tcp_tunnel(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10
    __update_time = 0
    __conn_timeout = 0

    __server_address = None

    def init_func(self, creator, crypto, crypto_configs, conn_timeout=720, is_ipv6=False, **kwargs):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_STREAM)

        self.set_socket(s)
        self.__conn_timeout = conn_timeout

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        return self.fileno

    def create_tunnel(self, server_address):
        server_ip = self.dispatcher.get_server_ip(server_address[0])
        if not server_ip: return False

        try:
            self.connect((server_ip, server_address[1]), timeout=8)
            logging.print_general("connecting", server_address)
        except socket.gaierror:
            logging.print_general("not_found_host", server_address)
            return False

        self.__server_address = server_address
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

                session_id, action, message = pkt_info
                if action == proto_utils.ACT_PONG: continue
                if action == proto_utils.ACT_PING:
                    session_id = self.dispatcher.session_id
                    self.send_msg_to_tunnel(session_id, proto_utils.ACT_PONG, b"")
                    continue

                self.dispatcher.handle_msg_from_tunnel(session_id, action, message)
            ''''''
        self.__update_time = time.time()
        return

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_tunnel_close()
        self.unregister(self.fileno)
        self.close()

        if self.is_conn_ok():
            logging.print_general("disconnect", self.__server_address)
        return

    def tcp_error(self):
        logging.print_general("tcp_error", self.__server_address)
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            logging.print_general("connecting_timeout", self.__server_address)
            self.delete_handler(self.fileno)
            return

        t = time.time()

        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            logging.print_general("connected_timeout", self.__server_address)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def connect_ok(self):
        self.__update_time = time.time()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        # 发送还没有连接的时候堆积的数据包
        if not self.writer.is_empty():
            self.__update_time = time.time()
            self.add_evt_write(self.fileno)

        logging.print_general("connected", self.__server_address)

        return

    def send_msg_to_tunnel(self, session_id, action, message):
        sent_pkt = self.__encrypt.build_packet(session_id, action, message)
        self.writer.write(sent_pkt)

        if self.is_conn_ok(): self.add_evt_write(self.fileno)

        self.__encrypt.reset()


class udp_tunnel(udp_handler.udp_handler):
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 5
    __update_time = 0
    __conn_timeout = 0
    __sent_queue = None

    __server_address = None
    __redundancy = None

    __enable_heartbeat = None
    __heartbeat_timeout = None
    __heartbeat_num = None
    # 已经发送的ping请求次数
    __ping_req_num = None

    def init_func(self, creator, crypto, crypto_configs, redundancy=False, conn_timeout=720, is_ipv6=False, **kwargs):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        self.__redundancy = redundancy

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)

        self.__conn_timeout = conn_timeout
        self.__sent_queue = []

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        self.__enable_heartbeat = kwargs.get("enable_heartbeat", False)
        self.__heartbeat_timeout = kwargs.get("heartbeat_timeout", 15)
        self.__heartbeat_num = kwargs.get("heartbeat_num", 3)
        self.__ping_req_num = 0

        return self.fileno

    def create_tunnel(self, server_address):
        server_ip = self.dispatcher.get_server_ip(server_address[0])

        if not server_ip: return False

        try:
            self.connect((server_ip, server_address[1]))
        except socket.gaierror:
            logging.print_general("not_found_host", server_address)
            return False

        self.__server_address = server_address
        logging.print_general("udp_open", server_address)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__update_time = time.time()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return True

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if action not in proto_utils.ACTS: return

        if action == proto_utils.ACT_PONG:
            self.__ping_req_num = 0
            self.__update_time = time.time()
            return

        if action == proto_utils.ACT_PING:
            self.__update_time = time.time()
            return

        self.dispatcher.handle_msg_from_tunnel(session_id, action, byte_data)
        self.__update_time = time.time()

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        logging.print_general("udp_error", self.__server_address)
        self.delete_handler(self.fileno)

    def __handle_conn_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__conn_timeout:
            logging.print_general("udp_timeout", self.__server_address)
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def __handle_heartbeat_timeout(self):
        t = time.time()
        if self.__ping_req_num == self.__heartbeat_num:
            self.delete_handler(self.fileno)
            return

        if t - self.__update_time >= self.__heartbeat_timeout:
            self.send_msg_to_tunnel(self.dispatcher.session_id, proto_utils.ACT_PING, b"")
            self.__ping_req_num += 1

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_timeout(self):
        if self.__enable_heartbeat:
            self.__handle_heartbeat_timeout()
        else:
            self.__handle_conn_timeout()

    def udp_delete(self):
        self.unregister(self.fileno)
        self.dispatcher.tell_tunnel_close()
        self.close()
        logging.print_general("udp_close", self.__server_address)

    def send_msg_to_tunnel(self, session_id, action, message):
        ippkts = self.__encrypt.build_packets(session_id, action, message, redundancy=self.__redundancy)
        self.__encrypt.reset()

        for ippkt in ippkts: self.send(ippkt)

        self.add_evt_write(self.fileno)
        self.__update_time = time.time()
