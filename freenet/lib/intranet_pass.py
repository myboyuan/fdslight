#!/usr/bin/env python3

import pywind.lib.reader as reader

import struct, socket, os

VER = 1

TYPE_PING = 0
TYPE_PONG = 1
TYPE_CONN_REQ = 2
TYPE_CONN_RESP = 3
TYPE_MSG_CONTENT = 4
TYPE_CONN_CLOSE = 5

TYPES = (
    TYPE_PING, TYPE_PONG,
    TYPE_CONN_REQ, TYPE_CONN_RESP,
    TYPE_MSG_CONTENT, TYPE_CONN_CLOSE,
)


class ProtoErr(Exception): pass


class parser(object):
    __reader = None
    __header_ok = None
    __length = None
    __type = None
    __results = None

    def __init__(self):
        self.__reader = reader.reader()
        self.__header_ok = False
        self.__length = 0
        self.__results = []

    def parse_header(self):
        if self.__reader.size() < 6: return
        v, self.__type, self.__length = struct.unpack("!BBI", self.__reader.read(6))
        self.__header_ok = True
        if self.__type not in TYPES:
            raise ProtoErr("unsupport protocol number %s" % self.__type)

    def parse_conn_request(self):
        if self.__reader.size() < 36:
            raise ProtoErr("wrong conn request content length")

        session_id, byte_addr, port, is_ipv6, _ = struct.unpack("!16s16sHBB", self.__reader.read(36))

        if is_ipv6:
            s_addr = socket.inet_ntop(socket.AF_INET6, byte_addr)
        else:
            s_addr = socket.inet_ntop(socket.AF_INET, byte_addr[0:4])

        self.__results.append(
            (self.__type, (session_id, s_addr, port, bool(is_ipv6),))
        )

    def parse_conn_response(self):
        if self.__length != 20:
            raise ProtoErr("wrong conn response content length")

        session_id, err_code = struct.unpack("!16si", self.__reader.read(20))
        self.__results.append(
            (self.__type, (session_id, err_code,))
        )

    def parse_conn_close(self):
        if self.__length != 16:
            raise ProtoErr("wrong conn close content length")
        session_id = self.__reader.read(16)
        self.__results.append(
            (self.__type, session_id,)
        )

    def parse_conn_data(self):
        if self.__length < 17:
            raise ProtoErr("wrong conn data content length")

        session_id = self.__reader.read(16)
        self.__length = self.__length - 16
        data = self.__reader.read(self.__length)

        self.__results.append(
            (self.__type, (session_id, data,))
        )

    def parse_body(self):
        if self.__reader.size() < self.__length: return
        self.__header_ok = False
        if self.__type == TYPE_CONN_REQ:
            self.parse_conn_request()
            return
        if self.__type == TYPE_CONN_RESP:
            self.parse_conn_response()
            return
        if self.__type == TYPE_CONN_CLOSE:
            self.parse_conn_close()
            return
        if self.__type == TYPE_MSG_CONTENT:
            self.parse_conn_data()
            return

        body_data = self.__reader.read(self.__length)
        self.__results.append(
            (self.__type, body_data,)
        )

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        if not self.__header_ok:
            self.parse_header()
        if not self.__header_ok: return
        self.parse_body()

    def get_result(self):
        res = None
        try:
            res = self.__results.pop(0)
        except IndexError:
            pass
        return res


class builder(object):
    def build_data(self, t, byte_data):
        if len(byte_data) > 0xffffff:
            raise ProtoErr("the data length must be less than 0xffffff")

        header = struct.pack("!BBI", VER, t, len(byte_data))

        return b"".join([header, byte_data])

    def build_ping(self, length=0):
        byte_data = os.urandom(length)

        return self.build_data(TYPE_PING, byte_data)

    def build_pong(self, length=0):
        byte_data = os.urandom(length)

        return self.build_data(TYPE_PONG, byte_data)

    def build_conn_request(self, session_id, ip_addr, port, is_ipv6=False):
        if is_ipv6:
            byte_addr = socket.inet_pton(socket.AF_INET6, ip_addr)
        else:
            byte_addr = socket.inet_pton(socket.AF_INET, ip_addr)
            byte_addr = byte_addr + bytes(12)

        byte_data = struct.pack("!16s16sHBB", session_id, byte_addr, port, int(is_ipv6), 0)

        return self.build_data(TYPE_CONN_REQ, byte_data)

    def build_conn_response(self, session_id, err_code):
        body_data = struct.pack("!16si", session_id, err_code)

        return self.build_data(TYPE_CONN_RESP, body_data)

    def build_conn_close(self, session_id):
        return self.build_data(TYPE_CONN_CLOSE, session_id)

    def build_conn_data(self, session_id, byte_data):
        wrap_data = self.build_data(TYPE_MSG_CONTENT, b"".join([session_id, byte_data, ]))

        return wrap_data
