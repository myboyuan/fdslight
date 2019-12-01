#!/usr/bin/env python3

import pywind.evtframework.handlers.ssl_handler as ssl_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import socket, time, random, os, ssl

import freenet.lib.logging as logging
import freenet.lib.socks2https as socks2https


class convert_client(ssl_handler.ssl_handelr):
    """把任意数据包转换成私有协议
    """
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

    def ssl_init(self, address, path, user, passwd, is_ipv6=False, ssl_on=False):
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

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_alpn_protocols(["http/1.1"])
        s = context.wrap_socket(s, do_handshake_on_connect=False)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def ssl_handshake_ok(self):
        logging.print_general("TLS handshake OK", self.__address)
        self.send_handshake_request()

    def connect_ok(self):
        logging.print_general("connect_ok", self.__address)
        if self.dispatcher.debug:
            print(self.socket.getpeername())
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

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
        logging.print_general("https_handshake_ok", self.__address)
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

    def rand_bytes(self):
        n = random.randint(0, 128)
        return os.urandom(n)

    def send_pong(self):
        if self.dispatcher.debug:
            print("send pong")
        data = self.rand_bytes()
        pong_data = self.__builder.build_pong(data)

        self.send_data(pong_data)

    def send_ping(self):
        if self.dispatcher.debug:
            print("send ping")
        data = self.rand_bytes()
        ping_data = self.__builder.build_ping(data)

        self.send_data(ping_data)

    def handle_pong(self):
        if self.dispatcher.debug:
            print("received pong")
        self.__time = time.time()

    def handle_conn_state(self, info):
        packet_id, err_code = info
        self.dispatcher.handle_conn_state(packet_id, err_code)

    def handle_tcp_data(self, info):
        packet_id, win_size, byte_data = info
        self.dispatcher.handle_tcp_data(packet_id, byte_data)

    def handle_udp_udplite_data(self, info):
        _id, address, port, _, byte_data = info
        self.dispatcher.handle_udp_udplite_data(_id, address, port, byte_data)

    def tcp_readable(self):
        if not self.__http_handshake_ok:
            self.handle_handshake_response()
            return

        self.__parser.input(self.reader.read())
        self.__time = time.time()

        while 1:
            try:
                self.__parser.parse()
            except socks2https.FrameError:
                logging.print_error()
                self.delete_handler(self.fileno)
                break
            rs = self.__parser.get_result()
            if not rs: break
            frame_type, info = rs

            if frame_type == socks2https.FRAME_TYPE_PING:
                self.send_pong()
                continue
            if frame_type == socks2https.FRAME_TYPE_PONG:
                self.handle_pong()
                continue
            if frame_type == socks2https.FRAME_TYPE_CONN_STATE:
                self.handle_conn_state(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_TCP_DATA:
                self.handle_tcp_data(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDP_DATA:
                self.handle_udp_udplite_data(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDPLITE_DATA:
                self.handle_udp_udplite_data(info)
                continue
            ''''''
        return

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        # 没有连接成功的处理方式
        if not self.is_conn_ok():
            logging.print_general("connect_fail", self.__address)
            self.delete_handler(self.fileno)
            return

        t = time.time()
        if t - self.__time > self.dispatcher.client_conn_timeout:
            logging.print_general("timeout", self.__address)
            self.delete_handler(self.fileno)
            return
        if t - self.__time > self.dispatcher.client_heartbeat_time:
            self.send_ping()
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        logging.print_general("server_disconnect", self.__address)
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        logging.print_general("disconnect", self.__address)
        self.dispatcher.tell_close_for_all()
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
        data = self.__builder.build_conn_frame(frame_type, packet_id, addr_type, host, port,
                                               byte_data=data)
        if self.dispatcher.debug:
            logging.print_general("send_conn_request,%s,(%s,%s)" % (frame_type, host, port,), self.__address)
        self.send_data(data)

    def send_tcp_data(self, packet_id, byte_data):
        if not self.is_conn_ok(): return

        ### 防止数据溢出
        while 1:
            if not byte_data: break
            wrap_data = self.__builder.build_tcp_frame_data(packet_id, byte_data[0:0xfff0])
            byte_data = byte_data[0xfff0:]
            self.writer.write(wrap_data)

        self.add_evt_write(self.fileno)

    def send_conn_close(self, packet_id):
        if not self.is_conn_ok(): return

        wrap_data = self.__builder.build_conn_state(packet_id, err_code=1)
        self.send_data(wrap_data)
