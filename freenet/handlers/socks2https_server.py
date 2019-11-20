#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.websocket as ws
import pywind.web.lib.httputils as httputils
import socket, time, urllib.request


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

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    # 是否已经成功握手
    __handshake_ok = None
    __caddr = None

    def init_func(self, creator_fd, cs, caddr):
        self.__handshake_ok = False
        self.__caddr = caddr

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

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
        if upgrade.lower() != "websocket":
            self.delete_handler(self.fileno)
            return
        connection = self.get_kv_value(kv, "connection")
        if connection.lower() != "upgrade":
            self.delete_handler(self.fileno)
            return
        sec_ws_key = self.get_kv_value(kv, "sec-websocket-key")
        if not sec_ws_key:
            self.delete_handler(self.fileno)
            return
        origin = self.get_kv_value(kv, "origin")
        if not origin:
            self.delete_handler(self.fileno)
            return
        ws_ver = self.get_kv_value(kv, "sec-websocket-version")

        try:
            v = int(ws_ver)
        except ValueError:
            self.delete_handler(self.fileno)
            return

        if v != 13:
            self.delete_handler(self.fileno)
            return

        sec_ws_proto = self.get_kv_value(kv, "sec-websocket-protocol")
        if not sec_ws_proto:
            self.delete_handler(self.fileno)
            return

        resp_headers = [
            ("Content-Length", "0"),
        ]
        resp_headers += [("Connection", "Upgrade",), ("Upgrade", "websocket",)]
        resp_headers += [("Sec-WebSocket-Accept", ws.gen_handshake_key(sec_ws_key))]
        resp_headers += [("Sec-WebSocket-Protocol", "socks2https")]

        self.__handshake_ok = True
        self.send_response("101 Switching Protocols", resp_headers)

    def send_response(self, status, headers):
        s = httputils.build_http1x_resp_header(status, headers)
        byte_data = s.encode("iso-8859-1")

        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)

    def get_kv_value(self, kv_pairs, name):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None

    def handle_request_data(self):
        pass

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.do_handshake()
            return
        self.handle_request_data()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def auth_user(self, uri):
        """验证用户是否合法
        :param uri:
        :return:
        """
        return True


class handler_for_tcp(tcp_handler.tcp_handler):
    def init_func(self, creator_fd, *args, **kwargs):
        pass

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_error(self):
        pass

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        pass


class handler_for_udp(udp_handler.udp_handler):
    def init_func(self, creator_fd, address, is_udplite=False, is_ipv6=False):
        pass

    def udp_readable(self, message, address):
        pass

    def udp_writable(self):
        pass

    def udp_delete(self):
        pass

    def udp_error(self):
        pass

    def udp_timeout(self):
        pass
