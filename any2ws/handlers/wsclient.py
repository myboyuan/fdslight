#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as websocket
import pywind.web.lib.httputils as httputils
import socket, time, random, sys, ssl


class wsclient(tcp_handler.tcp_handler):
    __is_delete = None
    __up_time = None

    __handshake_ok = None

    __encoder = None
    __decoder = None
    __address = None
    __ws_key = None
    __creator = None

    __conn_timout = None
    __url = None
    __auth_id = None

    __ssl_on = None
    __ssl_handshake_ok = None

    __tmp_sent_buf = None

    def init_func(self, creator_fd, address, url, auth_id, is_ipv6=False, ssl_on=False, conn_timeout=600):
        self.__is_delete = False
        self.__handshake_ok = False
        self.__encoder = websocket.encoder()
        self.__decoder = websocket.decoder()
        self.__address = address
        self.__ws_key = self.rand_string()
        self.__creator = creator_fd
        self.__url = url
        self.__auth_id = auth_id
        self.__ssl_on = ssl_on
        self.__conn_timout = conn_timeout
        self.__ssl_handshake_ok = False
        self.__tmp_sent_buf = []

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_alpn_protocols(["http/1.1"])
        s = context.wrap_socket(s, do_handshake_on_connect=False)

        self.set_socket(s)
        self.connect(address, timeout=5)

        return self.fileno

    def connect_ok(self):
        self.__up_time = time.time()
        self.register(self.fileno)

        print("connected server %s:%s" % self.__address)

        if self.__ssl_on:
            self.do_ssl_handshake()
        else:
            self.add_evt_read(self.fileno)
            self.send_handshake()

    def send_handshake(self):
        url = self.__url
        auth_id = self.__auth_id

        kv_pairs = [("Host", self.__address[0],), ("Connection", "Upgrade"), ("Upgrade", "websocket",),
                    ("Sec-WebSocket-Version", 13,), ("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64)",),
                    ("Accept-Language", "zh-CN,zh;q=0.8"), ("Sec-WebSocket-Key", self.__ws_key,),
                    ("X-Auth-Id", auth_id,)]

        s = httputils.build_http1x_req_header("GET", url, kv_pairs)

        self.writer.write(s.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

    def recv_handshake(self):
        size = self.reader.size()
        data = self.reader.read()

        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            self.delete_handler(self.fileno)
            sys.stderr.write("wrong http response header")
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
            self.delete_handler(self.fileno)
            return

        version, status = resp
        print(status)

        if status.find("101") != 0:
            self.delete_handler(self.fileno)
            sys.stderr.write("websocket handshake fail")
            return

        accept_ws_key = self.get_kv_pairs_value("Sec-WebSocket-Accept", kv_pairs)
        if accept_ws_key != websocket.gen_handshake_key(self.__ws_key):
            self.delete_handler(self.fileno)
            sys.stderr.write("websocket sec key wrong")
            return

        self.__handshake_ok = True
        if self.__tmp_sent_buf:
            self.add_evt_write(self.add_evt_write(self.fileno))

        while 1:
            try:
                self.writer.write(self.__tmp_sent_buf.pop(0))
            except IndexError:
                break

    def do_ssl_handshake(self):
        try:
            self.socket.do_handshake()
            self.__ssl_handshake_ok = True
            self.add_evt_read(self.fileno)
            self.send_handshake()
        except ssl.SSLWantReadError:
            self.add_evt_read(self.fileno)
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)

    def evt_read(self):
        if not self.is_conn_ok():
            super().evt_read()
            return

        if not self.__ssl_on:
            super().evt_read()
            return

        if not self.__ssl_handshake_ok:
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return

        try:
            super().evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLWantReadError:
            if self.reader.size() > 0:
                self.tcp_readable()
        except ssl.SSLZeroReturnError:
            if self.reader.size() > 0:
                self.tcp_readable()
            if self.handler_exists(self.fileno): self.delete_handler(self.fileno)

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.recv_handshake()
            return

        self.__decoder.input(self.reader.read())

        while 1:
            self.__decoder.parse()
            if self.__decoder.can_read_data() and self.__decoder.frame_ok():
                data = self.__decoder.get_data()

                self.__decoder.reset()

                if self.__decoder.opcode not in (
                        websocket.OP_PING, websocket.OP_PONG, websocket.OP_BIN, websocket.OP_CLOSE):
                    self.delete_handler(self.fileno)
                    break

                if self.__decoder.opcode == websocket.OP_BIN:
                    self.send_message_to_handler(self.fileno, self.__creator, data)
                    self.__up_time = time.time()
                    continue

                if self.__decoder.opcode == websocket.OP_PONG:
                    self.handle_pong()
                    continue

                if self.__decoder.opcode == websocket.OP_PING:
                    self.handle_ping()
                    continue

                if self.__decoder.opcode == websocket.OP_CLOSE:
                    self.handle_close()
                    return

            if not self.__decoder.continue_parse(): break
        ''''''

    def handle_ping(self):
        data = self.__encoder.build_pong(b"")

        self.add_evt_write(self.fileno)
        self.writer.write(data)

    def handle_pong(self):
        pass

    def handle_close(self):
        data = self.__encoder.build_close(b"")

        self.add_evt_write(self.fileno)
        self.writer.write(data)
        self.delete_this_no_sent_data()

    def evt_write(self):
        if not self.is_conn_ok():
            super().evt_write()
            return

        if not self.__ssl_handshake_ok:
            self.remove_evt_write(self.fileno)
            self.do_ssl_handshake()

        if not self.__ssl_handshake_ok: return
        try:
            super(wsclient, self).evt_write()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLEOFError:
            self.delete_handler(self.fileno)

    def tcp_writable(self):
        if self.writer.size() == 0:
            self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

        t = time.time()
        if not self.__handshake_ok and t - self.__up_time > 15:
            self.delete_handler(self.fileno)
            return

        if t - self.__up_time > self.__conn_timout:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

        print("disconnect %s:%s" % self.__address)

        if self.handler_exists(self.__creator): self.dispatcher.get_handler(self.__creator).tell_ws_delete()

    def rand_string(self):
        chs = []
        for i in range(8):
            chs.append(chr(random.randint(48, 122)))

        return "".join(chs)

    def get_kv_pairs_value(self, name, kv_pairs):
        for k, v in kv_pairs:
            if k.lower() == name.lower():
                return v

        return None

    def message_from_handler(self, from_fd, byte_data):
        data = self.__encoder.build_frame(byte_data, 1, 0, websocket.OP_BIN)

        if self.__handshake_ok:
            self.writer.write(data)
            self.add_evt_write(self.fileno)
        else:
            self.__tmp_sent_buf.append(data)
