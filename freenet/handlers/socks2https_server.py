#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.websocket as ws
import pywind.web.lib.httputils as httputils
import socket, time, urllib.parse, random, os

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

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    # 是否已经成功握手
    __handshake_ok = None
    __caddr = None

    __packet_id_map = None

    __parser = None
    __builder = None

    __time = None
    # 客户端传送过来的窗口大小
    __win_size = None

    def init_func(self, creator_fd, cs, caddr):
        self.__handshake_ok = False
        self.__caddr = caddr
        self.__packet_id_map = {}

        self.__parser = socks2https.parser()
        self.__builder = socks2https.builder()

        self.__time = time.time()

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

        resp_headers = [
            ("Content-Length", "0"),
        ]

        # 验证用户是否合法
        if not self.auth_user(uri):
            self.send_403_response()
            return

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

    def send_403_response(self):
        self.send_response("403 Forbidden", [("Content-Length", 0,)])
        self.delete_this_no_sent_data()

    def get_kv_value(self, kv_pairs, name):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None

    def handle_tcp_data(self, info):
        _id, tcp_data = info
        if _id not in self.__packet_id_map: return

    def handle_udp_udplite_data(self, info, is_udplite=False):
        _id, win_size, address, port, byte_data = info
        # 如果不存在那么创建一个handler
        if _id not in self.__packet_id_map:
            fd = self.create_handler(self.fileno, handler_for_udp, (address, port), _id, is_udplite=is_udplite,
                                     is_ipv6=False)
            self.__packet_id_map[_id] = fd
        fd = self.__packet_id_map[_id]

    def handle_tcp_conn_request(self, info):
        _id, win_size, address, port, byte_data = info
        # 如果包ID存在那么发送错误
        if _id in self.__packet_id_map:
            return

        fd = self.create_handler(self.fileno, handler_for_tcp, (address, port), _id, is_ipv6=False)
        self.__packet_id_map[_id] = fd

    def handle_request_data(self):
        self.__parser.input(self.reader.read())

        try:
            self.__parser.parse()
        except socks2https.FrameError:
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
            if frame_type == socks2https.FRAME_TYPE_TCP_DATA:
                self.handle_tcp_data(info)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDP_DATA:
                self.handle_udp_udplite_data(info, is_udplite=False)
                continue
            if frame_type == socks2https.FRAME_TYPE_UDPLITE_DATA:
                self.handle_udp_udplite_data(info, is_udplite=True)
                continue
            if frame_type == socks2https.FRAME_TYPE_TCP_CONN:
                self.handle_tcp_conn_request(info)
                continue
            ''''''
        return

    def send_data(self, byte_data):
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)

    def rand_bytes(self):
        n = random.randint(0, 128)
        return os.urandom(n)

    def send_pong(self):
        data = self.rand_bytes()
        pong_data = self.__builder.build_pong(data)

        self.send_data(pong_data)

    def handle_pong(self):
        self.__time = time.time()

    def send_ping(self):
        data = self.rand_bytes()
        ping_data = self.__builder.build_ping(data)

        self.send_data(ping_data)

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
        t = time.time()
        if t - self.__time > self.dispatcher.conn_timeout:
            self.delete_handler(self.fileno)
            return

        if t - self.__time > self.dispatcher.heartbeat_timeout:
            self.send_ping()
            return

        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        for packet_id, fd in self.__packet_id_map.items():
            self.delete_handler(fd)
        self.unregister(self.fileno)
        self.close()

    def auth_user(self, uri):
        """验证用户是否合法
        :param uri:
        :return:
        """
        users_info = self.dispatcher.get_users()
        p = uri.find("?")
        if p < 1: return False

        p += 1
        s = uri[p:]
        result = urllib.parse.parse_qs(s)

        users = result.get("user", [])
        passwds = result.get("passwd", [])

        if not users or not passwds: return False

        user = users.pop(0)
        passwd = passwds.pop(0)

        rs = False

        for user_info in users_info:
            u = users_info.get("username", None)
            p = users_info.get("password", None)
            if u != user and p != passwd: continue
            rs = True

        return rs

    def tell_tcp_close(self, packet_id):
        pass

    def tell_udp_udplite_close(self, packet_id):
        pass

    def message_from_handler(self, from_fd, byte_data):
        pass


class handler_for_tcp(tcp_handler.tcp_handler):
    __creator = None
    __packet_id = None
    __time = None

    def init_func(self, creator_fd, address, packet_id, is_ipv6=False):
        self.__creator = creator_fd
        self.__packet_id = packet_id
        self.__time = time.time()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)

        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_error(self):
        pass

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.dispatcher.get_handler(self.__creator).tell_tcp_close(self.__packet_id)
            return
        t = time.time()
        if t - self.__time > self.dispatcher.conn_timeout:
            self.delete_handler(self.fileno)
            return

    def tcp_delete(self):
        pass


class handler_for_udp(udp_handler.udp_handler):
    __creator = None
    __packet_id = None
    __time = None

    def init_func(self, creator_fd, address, packet_id, is_udplite=False, is_ipv6=False):
        self.__creator = creator_fd
        self.__packet_id = packet_id
        self.__time = time.time()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_DGRAM)
        self.set_socket(s)

        return self.fileno

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

    def msg_send(self, address, byte_data):
        pass
