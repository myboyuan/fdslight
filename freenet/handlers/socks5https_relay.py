#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler

import socket, time

import freenet.lib.socks2https as socks2https
import freenet.lib.utils as utils
import freenet.lib.logging as logging


class listener(tcp_handler.tcp_handler):
    __cfg_name = None
    __is_ipv6 = None
    __conn_timeout = None

    def init_func(self, creator_fd, address, cfg_name, conn_timeout=60, is_ipv6=False):
        self.__cfg_name = cfg_name
        self.__is_ipv6 = is_ipv6
        self.__conn_timeout = conn_timeout

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr, self.__cfg_name, conn_timeout=self.__conn_timeout,
                                is_ipv6=self.__is_ipv6)
        ''''''


class handler(tcp_handler.tcp_handler):
    __caddr = None
    __cfg_name = None
    __is_ipv6 = None
    __time = None
    __conn_timeout = None
    __is_sent_conn = None
    __conn_ok = None
    __packet_id = None
    __creator = None

    @property
    def debug(self):
        return self.dispatcher.debug

    def init_func(self, creator_fd, cs, caddr, config_name, conn_timeout=60, is_ipv6=False):
        self.__creator = creator_fd
        self.__caddr = caddr
        self.__cfg_name = config_name
        self.__is_ipv6 = is_ipv6
        self.__time = time.time()
        self.__conn_timeout = conn_timeout
        self.__is_sent_conn = False
        self.__conn_ok = False

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        logging.print_general("relay_accept:%s" % config_name, caddr)

        return self.fileno

    def send_conn_request(self):
        self.__packet_id = self.dispatcher.alloc_packet_id(self.fileno)
        _, address = self.dispatcher.get_relay_service(self.__cfg_name)

        is_ipv6 = False
        is_ipv4 = False

        if utils.is_ipv6_address(address[0]): is_ipv6 = True
        if utils.is_ipv4_address(address[0]): is_ipv4 = True

        if is_ipv4:
            _t = socks2https.ADDR_TYPE_IP
        elif is_ipv6:
            _t = socks2https.ADDR_TYPE_IPv6
        else:
            _t = socks2https.ADDR_TYPE_DOMAIN
        self.dispatcher.send_conn_frame(socks2https.FRAME_TYPE_TCP_CONN, self.__packet_id, address[0], address[1], _t)

    def tcp_readable(self):
        if not self.__is_sent_conn:
            self.send_conn_request()
            self.__is_sent_conn = True
        # 防止客户端大量发送数据,使服务器内存耗尽
        if not self.__conn_ok and self.reader.size() > 0xfffff:
            _ = self.reader.read()
            self.delete_handler(self.fileno)
            return

        if not self.__conn_ok: return
        self.__time = time.time()
        self.dispatcher.send_tcp_data(self.__packet_id, self.reader.read())

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        if self.debug:
            logging.print_general("client_disconnect", self.__caddr)
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        if self.debug:
            logging.print_general("disconnect", self.__caddr)
        self.dispatcher.free_packet_id(self.__packet_id)

        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, byte_data):
        self.__time = time.time()
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)

    def tell_conn_ok(self):
        self.__conn_ok = True

    def tell_close(self):
        self.delete_handler(self.fileno)
