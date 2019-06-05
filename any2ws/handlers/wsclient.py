#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as websocket
import pywind.web.lib.httputils as httputils
import socket, time, random, sys


class wsclient(tcp_handler.tcp_handler):
    __is_delete = None
    __up_time = None

    __handshake_ok = None

    __encoder = None
    __decoder = None
    __address = None
    __ws_key = None
    __creator = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__is_delete = False
        self.__handshake_ok = False
        self.__encoder = websocket.encoder()
        self.__decoder = websocket.decoder()
        self.__address = address
        self.__ws_key = self.rand_string()
        self.__creator = creator_fd

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.__up_time = time.time()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.send_handshake()

    def send_handshake(self):
        cfgs = self.configs.get("remote", {})
        url = cfgs.get("url", "/")
        auth_id = cfgs["auth_id"]

        kv_pairs = [("Host", self.__address[0],), ("Connection", "Upgrade"), ("Upgrade", "websocket",),
                    ("Sec-WebSocket-Version", 13,), ("User-Agent",
                                                     "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",),
                    ("Accept-Language", "zh-CN,zh;q=0.8"), ("Sec-WebSocket-Key", self.__ws_key,),
                    ("X-Auth-Id", auth_id,)]

        s = httputils.build_http1x_req_header("GET", url, kv_pairs)

        self.writer.write(s.encode("is-8859-1"))
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

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.recv_handshake()

        if not self.__handshake_ok: return

        self.send_message_to_handler(self.fileno, self.__creator, self.reader.read())
        self.__up_time = time.time()

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        if self.__is_delete: return
        self.__is_delete = True
        self.unregister(self.fileno)
        self.close()

    @property
    def configs(self):
        return self.dispatcher.configs.get("remote", {})

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
