#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler

import socket, time, ssl


class listener(tcp_handler.tcp_handler):
    def init_func(self, creator_fd, address, is_ipv6=False):
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


class http_socks5_listener(listener):
    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, http_socks5_handler, cs, caddr)
        ''''''


class raw_tcp_listener(listener):
    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, raw_tcp_handler, cs, caddr)


class http_socks5_handler(tcp_handler.tcp_handler):
    ### 是否是socks5请求
    __is_socks5 = None
    ### http请求相关变量
    # 是否是http隧道模式
    __is_http_tunnel_mode = None
    # 是否是http chunked模式
    __is_http_chunked = None
    # 总共需要响应的数据长度
    __is_http_response_length = None
    # http已经响应的数据长度
    __http_responsed_length = None
    # 响应是否结束
    __is_http_finished = None

    ### socks5相关变量

    def init_func(self, creator_fd, cs, caddr):
        self.__is_socks5 = False


class socks5_udp_handler(udp_handler.udp_handler):
    pass


class convert_client(tcp_handler.tcp_handler):
    """把任意数据包转换成私有协议
    """
    __creator = None

    __wait_sent = None

    def init_func(self, creator_fd, address, is_ipv6=False, ssl_on=False):
        """
        :param creator_fd:
        :param address:
        :param is_ipv6:
        :param ssl_on: 是否开启ssl加密,默认不开启,用于调试
        :return:
        """
        self.__creator = creator_fd
        self.__wait_sent = []

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def send_handshake_request(self, user, passwd):
        """发送握手请求
        :param user:
        :param passwd:
        :return:
        """
        pass

    def handle_handshake_response(self):
        """处理握手响应
        :return:
        """
        pass

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        # 没有连接成功的处理方式
        if not self.is_conn_ok():
            return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_data(self, byte_data):
        """发送数据
        :param byte_data:
        :return:
        """
        pass

    def message_from_handler(self, from_fd, byte_data):
        # 核对数据包来源
        if from_fd != self.__creator: return
        self.send_data(byte_data)


class raw_tcp_handler(tcp_handler.tcp_handler):
    __caddr = None
    __convert_fd = None

    def init_func(self, creator_fd, cs, caddr):
        self.__caddr = caddr
        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_readable(self):
        self.send_message_to_handler(self.fileno, self.__convert_fd, self.reader.read())

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
