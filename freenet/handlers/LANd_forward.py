#!/usr/bin/env python3

import pywind.evtframework.handlers.ssl_handler as ssl_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import socket, time, random, os, ssl
import freenet.lib.logging as logging
import freenet.lib.intranet_pass as intranet_pass


class client(ssl_handler.ssl_handelr):
    """把任意数据包转换成私有协议
    """
    __wait_sent = None
    __address = None
    __path = None
    __http_handshake_ok = None
    __http_handshake_key = None
    __parser = None
    __builder = None
    __time = None
    __ssl_ok = None

    __role = None
    __auth_id = None
    __session_id = None

    def ssl_init(self, address, path, auth_id, role, session_id=None, is_ipv6=False, ssl_on=False):
        self.__wait_sent = []
        self.__address = address
        self.__path = path
        self.__http_handshake_ok = False
        self.__parser = intranet_pass.parser()
        self.__builder = intranet_pass.builder()
        self.__time = time.time()
        self.__ssl_ok = False
        self.__role = role
        self.__auth_id = auth_id
        self.__session_id = session_id

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
        self.__ssl_ok = True
        logging.print_general("TLS handshake OK", self.__address)
        self.send_handshake_request()

    def connect_ok(self):
        logging.print_general("connect_ok", self.__address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        # 注意这里要加入写事件,让TLS能够握手成功
        self.add_evt_write(self.fileno)
        self.set_timeout(self.fileno, 10)

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
            "User-Agent", "LANd_pass",),
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

    def tcp_readable(self):
        if not self.__http_handshake_ok:
            self.handle_handshake_response()
            return

        self.__parser.input(self.reader.read())
        self.__time = time.time()

        while 1:
            pass

    def tcp_writable(self):
        if not self.__ssl_ok: return
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        pass

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
        self.send_now()
