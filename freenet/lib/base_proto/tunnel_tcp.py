#!/usr/bin/env python3
"""TCP隧道
协议格式如下:
version:4bit 协议版本
action:4 bit 包动作
tot_length: 2 bytes 包的总长度
real_length: 2 bytes 加密前的长度
"""
ACT_AUTH = 1
ACT_PING = 2
ACT_PONG = 3
ACT_DATA = 4
ACT_DNS = 5

ACTS = (
    ACT_AUTH, ACT_PING, ACT_PONG,
    ACT_DATA, ACT_DNS,
)

MIN_FIXED_HEADER_SIZE = 5

import pywind.lib.reader as reader


class ProtoError(Exception): pass


class builder(object):
    __fixed_hdr_size = 0

    def __init__(self, fixed_hdr_size):
        self.__fixed_hdr_size = fixed_hdr_size

    def __build_proto_headr(self, tot_len, real_size, action):
        T = (
            (1 << 4) | (action & 0x0f),
            (tot_len & 0xff00) >> 8,
            tot_len & 0x00ff,
            (real_size & 0xff00) >> 8,
            real_size & 0x00ff,
        )
        return bytes(T)

    def build_packet(self, action, pkt_len, byte_data):
        tot_len = self.get_payload_length(pkt_len)
        base_hdr = self.__build_proto_headr(tot_len, pkt_len, action)

        e_hdr = self.wrap_header(base_hdr)
        e_body = self.wrap_body(pkt_len, byte_data)

        return b"".join((e_hdr, e_body,))

    def wrap_header(self, base_hdr):
        """重写这个方法"""
        pass

    def wrap_body(self, size, body_data):
        """重写这个方法"""
        pass

    def reset(self):
        pass

    def get_payload_length(self, pkt_len):
        """获取负载长度,加密前后可能数据包长度不一致,重写这个方法"""
        return pkt_len


class parser(object):
    __reader = None
    __fixed_hdr_size = MIN_FIXED_HEADER_SIZE
    # 数据负荷大小
    __tot_length = 0
    # 解密后的数据大小
    __real_length = 0
    __header_ok = False
    __action = 0
    __results = None

    def __init__(self, fixed_hdr_size):
        """
        :param fixed_hdr_size: 固定头长度
        """
        self.__reader = reader.reader()
        self.__fixed_hdr_size = fixed_hdr_size
        self.__results = []

    def __parse_header(self, hdr):
        n = hdr[0]
        version = (n & 0xf0) >> 4
        action = n & 0x0f
        tot_len = (hdr[1] << 8) | hdr[2]
        real_size = (hdr[3] << 8) | hdr[4]

        return (action, tot_len, real_size,)

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        size = self.__reader.size()

        if self.__header_ok:
            if size < self.__tot_length: return
            e_body = self.__reader.read(self.__tot_length)
            body = self.unwrap_body(self.__real_length, e_body)
            self.__results.append((self.__action, body,))
            self.reset()
            return
        if self.__reader.size() < self.__fixed_hdr_size: return
        hdr = self.unwrap_header(self.__reader.read(self.__fixed_hdr_size))
        if not hdr:
            self.reset()
            return
        self.__action, self.__tot_length, self.__real_length = self.__parse_header(hdr)
        self.__header_ok = True

    def unwrap_header(self, header):
        """重写这个方法"""
        pass

    def unwrap_body(self, real_size, body_data):
        """重写这个方法"""
        pass

    def reset(self):
        self.__tot_length = 0
        self.__header_ok = False
        self.__real_length = 0

    def can_continue_parse(self):
        size = self.__reader.size()
        if not self.__header_ok and size < self.__fixed_hdr_size: return False
        if not self.__header_ok: return True

        return size >= self.__tot_length

    def get_pkt(self):
        try:
            return self.__results.pop(0)
        except IndexError:
            return None
