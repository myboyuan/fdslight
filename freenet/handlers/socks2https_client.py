#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import socket, time, ssl, random

import freenet.lib.logging as logging
import freenet.lib.socks2https as socks2https


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

    def handle_data(self, byte_data):
        pass


class socks5_udp_handler(udp_handler.udp_handler):
    def handle_data(self, byte_data):
        pass


class convert_client(tcp_handler.tcp_handler):
    """把任意数据包转换成私有协议
    """
    __creator = None
    __wait_sent = None
    __address = None
    __path = None
    __user = None
    __passwd = None

    __http_handshake_ok = None
    __http_handshake_key = None
    __parser = None
    __builder = None

    __time = None

    def init_func(self, creator_fd, address, path, user, passwd, is_ipv6=False, ssl_on=False):
        """
        :param creator_fd:
        :param address:
        :param is_ipv6:
        :param ssl_on: 是否开启ssl加密,默认不开启,用于调试
        :return:
        """
        self.__creator = creator_fd
        self.__wait_sent = []
        self.__address = address
        self.__path = path
        self.__user = user
        self.__passwd = passwd
        self.__http_handshake_ok = False
        self.__parser = socks2https.parser()
        self.__builder = socks2https.builder()
        self.__time = time.time()

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

    def rand_string(self, length=8):
        seq = []
        for i in range(length):
            n = random.randint(65, 122)
            seq.append(chr(n))

        s = "".join(seq)
        self.__http_handshake_key = s

        return s

    def send_handshake_request(self):
        """发送握手请求
        :param user:
        :param passwd:
        :return:
        """
        uri = "%s?user=%s&passwd=%s" % (self.__path, self.__user, self.__passwd)

        kv_pairs = [("Connection", "Upgrade"), ("Upgrade", "websocket",), (
            "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:67.0) Gecko/20100101 Firefox/67.0",),
                    ("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"),
                    ("Sec-WebSocket-Version", 13,), ("Sec-WebSocket-Key", self.rand_string(),),
                    ("Sec-WebSocket-Protocol", "Socks2Https")]

        if int(self.__address[1]) == 443:
            host = ("Host", self.__address[0],)
            origin = ("Origin", "https://%s" % self.__address[0])
        else:
            host = ("Host", "%s:%s" % self.__address,)
            origin = ("Origin", "https://%s:%s" % self.__address,)

        kv_pairs.append(host)
        kv_pairs.append(origin)

        s = httputils.build_http1x_req_header("GET", uri, kv_pairs)

        self.writer.write(s.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

    def handle_handshake_response(self):
        """处理握手响应
        :return:
        """
        size = self.reader.size()
        data = self.reader.read()

        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            logging.print_general("wrong_http_response_header", self.__address)
            self.delete_handler(self.fileno)
            return

        if p < 0:
            self.reader._putvalue(data)
            return
        p += 4

        self.reader._putvalue(data[p:])

        s = data[0:p].decode("iso-8859-1")

        try:
            resp, kv_pairs = httputils.parse_http1x_response_header(s)
        except httputils.Http1xHeaderErr:
            logging.print_general("wrong_http_reponse_header", self.__address)
            self.delete_handler(self.fileno)
            return

        version, status = resp

        if status.find("101") != 0:
            logging.print_general("https_handshake_error:%s" % status, self.__address)
            self.delete_handler(self.fileno)
            return

        accept_key = self.get_http_kv_pairs("sec-websocket-accept", kv_pairs)
        if wslib.gen_handshake_key(self.__http_handshake_key) != accept_key:
            logging.print_general("https_handshake_error:wrong websocket response key", self.__address)
            self.delete_handler(self.fileno)
            return

        self.__http_handshake_ok = True
        logging.print_general("http_handshake_ok", self.__address)
        # 发送还没有连接的时候堆积的数据包
        if self.__wait_sent: self.add_evt_write(self.fileno)
        while 1:
            try:
                self.writer.write(self.__wait_sent.pop(0))
            except IndexError:
                break
            ''''''
        ''''''

    def get_http_kv_pairs(self, name, kv_pairs):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return

    def send_pong(self):
        pass

    def handle_pong(self):
        pass

    def handle_tcp_conn_state(self, info):
        pass

    def handle_recv(self, info):
        packet_id, byte_data = info
        fd = self.dispatcher.get_conn_info(packet_id)

        if fd < 0: return

        self.dispatcher.get_handler(fd).handle_data(byte_data)

    def tcp_readable(self):
        if not self.__http_handshake_ok:
            self.handle_handshake_response()
            return

        self.__parser.input(self.reader.read())
        try:
            self.__parser.parse()
        except socks2https.FrameError:
            logging.print_error()
            self.delete_handler(self.fileno)
            return

        while 1:
            rs = self.__parser.get_result()
            if not rs: break
            frame_type, info = rs

            if frame_type == socks2https.FRAME_TYPE_PING:
                self.send_pong()
                continue
            if frame_type == socks2https.FRAME_TYPE_PONG:
                self.handle_pong()
                continue
            if frame_type == socks2https.FRAME_TYPE_TCP_CONN_STATE:
                self.handle_tcp_conn_state(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_TCP_DATA:
                self.handle_recv(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDP_DATA:
                self.handle_recv(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDPLITE_DATA:
                self.handle_recv(info)
                continue
            ''''''
        return

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
        if not self.__http_handshake_ok:
            self.__wait_sent.append(byte_data)
            return
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)

    def send_conn_request(self, frame_type, packet_id, host, port, addr_type, data=b""):
        data = self.__builder.build_conn_frame(frame_type, packet_id, addr_type, host, port, win_size=1200,
                                               byte_data=data)
        self.send_data(data)

    def send_tcp_data(self, packet_id, byte_data):
        data = self.__builder.build_tcp_frame_data(packet_id, byte_data)
        self.send_data(data)


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
