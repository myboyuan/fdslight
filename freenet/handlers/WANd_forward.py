#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as ws
import pywind.web.lib.httputils as httputils
import socket, time, random, os
import freenet.lib.logging as logging
import freenet.lib.intranet_pass as intranet_pass


class listener(tcp_handler.tcp_handler):
    __is_ipv6 = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__is_ipv6 = is_ipv6

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

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr, self.__auth_id, is_ipv6=self.__is_ipv6)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    # 是否已经成功握手
    __handshake_ok = None
    __caddr = None
    __parser = None
    __builder = None

    __time = None
    __role = None

    def init_func(self, creator_fd, cs, caddr, is_ipv6=False):

        self.__handshake_ok = False
        self.__caddr = caddr

        self.__parser = intranet_pass.parser()
        self.__builder = intranet_pass.builder()

        self.__time = time.time()

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        logging.print_general("connect_ok", self.__caddr)

        return self.fileno

    def do_handshake(self):
        size = self.reader.size()
        rdata = self.reader.read()
        p = rdata.find(b"\r\n\r\n")

        if p < 5 and size > 2048:
            self.delete_handler(self.fileno)
            return

        s = rdata.decode("iso-8859-1")
        try:
            rq, kv = httputils.parse_htt1x_request_header(s)
        except httputils.Http1xHeaderErr:
            self.delete_handler(self.fileno)
            return

        m, uri, ver = rq

        if ver.lower() != "http/1.1":
            self.delete_handler(self.fileno)
            return

        if m != "GET":
            self.delete_handler(self.fileno)
            return

        upgrade = self.get_kv_value(kv, "upgrade")
        if not upgrade:
            self.send_403_response()
            return
        if upgrade.lower() != "websocket":
            self.send_403_response()
            return

        connection = self.get_kv_value(kv, "connection")
        if not connection:
            self.send_403_response()
            return
        if connection.lower() != "upgrade":
            self.send_403_response()
            return

        sec_ws_key = self.get_kv_value(kv, "sec-websocket-key")
        if not sec_ws_key:
            self.send_403_response()
            return

        origin = self.get_kv_value(kv, "origin")
        if not origin:
            self.send_403_response()
            return
        ws_ver = self.get_kv_value(kv, "sec-websocket-version")

        try:
            v = int(ws_ver)
        except ValueError:
            self.send_403_response()
            return

        if v != 13:
            self.send_403_response()
            return

        sec_ws_proto = self.get_kv_value(kv, "sec-websocket-protocol")
        if not sec_ws_proto:
            self.send_403_response()
            return

        auth_id = self.get_kv_value(kv, "x-auth-id")
        if not auth_id:
            self.send_403_response()
            return

        role = self.get_kv_value(kv, "x-role")
        if not role:
            self.send_403_response()
            return

        self.__role = role.lower()
        if self.__role not in ("cs", "ms",):
            self.send_403_response()
            return

        if self.__role == "ms":
            session_id = self.get_kv_value(kv, "x-session-id")
            if not session_id:
                self.send_403_response()
                return

        resp_headers = [
            ("Content-Length", "0"),
        ]

        resp_headers += [("Connection", "Upgrade",), ("Upgrade", "websocket",)]
        resp_headers += [("Sec-WebSocket-Accept", ws.gen_handshake_key(sec_ws_key))]
        resp_headers += [("Sec-WebSocket-Protocol", "socks2https")]

        logging.print_general("handshake_ok", self.__caddr)

        self.__handshake_ok = True
        self.send_response("101 Switching Protocols", resp_headers)

    def send_response(self, status, headers):
        s = httputils.build_http1x_resp_header(status, headers)
        byte_data = s.encode("iso-8859-1")

        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)

    def send_403_response(self):
        self.send_response("403 Forbidden", [("Content-Length", 0,)])
        self.delete_this_no_sent_data()

    def get_kv_value(self, kv_pairs, name):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None

    def handle_ping(self):
        pass

    def handle_pong(self):
        pass

    def handle_data(self):
        rdata = self.reader.read()
        self.__parser.input(rdata)
        self.__time = time.time()

        while 1:
            try:
                self.__parser.parse()
            except intranet_pass.ProtoErr:
                self.delete_handler(self.fileno)
                return

            rs = self.__parser.get_result()
            if not rs: break
            _type, o = rs

            if _type == intranet_pass.TYPE_PING:
                self.handle_ping()
                continue
            if _type == intranet_pass.TYPE_PONG:
                self.handle_pong()
                continue

            if _type == intranet_pass.TYPE_MSG_CONTENT:
                self.handle_conn_data(*o)
                continue

            if _type == intranet_pass.TYPE_CONN_CLOSE:
                self.handle_conn_close(o)
                continue

            if _type == intranet_pass.TYPE_CONN_RESP:
                self.handle_conn_response(*o)
                continue
            ''''''

    def send_data(self, byte_data):
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
        self.send_now()

    def rand_bytes(self):
        n = random.randint(0, 128)
        return os.urandom(n)

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.do_handshake()
            return
        self.handle_data()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_error(self):
        logging.print_general("client_disconnect", self.__caddr)
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_conn_request(self, session_id, remote_addr, remote_port, is_ipv6=False):
        byte_data = self.__builder.build_conn_request(session_id, remote_addr, remote_port, is_ipv6=is_ipv6)
        self.send_data(byte_data)

    def handle_conn_response(self, session_id, err_code):
        """处理客户端发送过来的连接响应帧
        """
        if err_code:
            self.dispatcher.tell_conn_fail(session_id)
        else:
            self.dispatcher.tell_conn_ok(session_id)

    def handle_conn_data(self, session_id, byte_data):
        pass

    def handle_conn_close(self, session_id):
        pass
