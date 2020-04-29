#!/usr/bin/env python3
"""TCP隧道
协议格式如下:
session_id:16 byte 会话ID,16 bytes的MD5值
payload_md5:16 byte 未加密的内容的MD5值
reverse:4bit 保留
action:4 bit 包动作
tot_length: 2 bytes 包的总长度
real_length: 2 bytes 加密前的长度
"""
MIN_FIXED_HEADER_SIZE = 37

import pywind.lib.reader as reader
import freenet.lib.base_proto.utils as proto_utils
import struct

_FMT = "!16s16sbHH"


class builder(object):
    __fixed_hdr_size = 0

    def __init__(self, fixed_hdr_size):
        self.__fixed_hdr_size = fixed_hdr_size
        if fixed_hdr_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "min fixed header size is %s" % MIN_FIXED_HEADER_SIZE)

    def __build_proto_headr(self, session_id, payload_m5, tot_len, real_size, action):
        """
        seq = [
            session_id, payload_m5,
        ]

        T = (
            action & 0x0f,
            (tot_len & 0xff00) >> 8,
            tot_len & 0x00ff,
            (real_size & 0xff00) >> 8,
            real_size & 0x00ff,
        )

        seq.append(bytes(T))

        return b"".join(seq)
        """
        res = struct.pack(
            _FMT, session_id, payload_m5, action, tot_len, real_size
        )

        return res

    def build_packet(self, session_id, action, byte_data):
        if len(session_id) != 16: raise proto_utils.ProtoError("the size of session_id must be 16")

        seq = []

        a, b = (0, 60000,)

        while 1:
            _byte_data = byte_data[a:b]
            if not _byte_data: break

            pkt_len = len(_byte_data)
            tot_len = self.get_payload_length(pkt_len)
            payload_md5 = proto_utils.calc_content_md5(_byte_data)
            base_hdr = self.__build_proto_headr(session_id, payload_md5, tot_len, pkt_len, action)

            e_hdr = self.wrap_header(base_hdr)
            e_body = self.wrap_body(pkt_len, _byte_data)

            seq.append(b"".join((e_hdr, e_body,)))
            a, b = (b, b + 60000,)

        return b"".join(seq)

    def wrap_header(self, base_hdr):
        """重写这个方法"""
        return base_hdr

    def wrap_body(self, size, body_data):
        """重写这个方法"""
        return body_data

    def reset(self):
        pass

    def get_payload_length(self, pkt_len):
        """获取负载长度,加密前后可能数据包长度不一致,重写这个方法"""
        return pkt_len

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass


class parser(object):
    __reader = None
    __fixed_hdr_size = MIN_FIXED_HEADER_SIZE
    __session_id = None
    __payload_md5 = None
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

        if fixed_hdr_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "min fixed header size is %s" % MIN_FIXED_HEADER_SIZE)

    def __parse_header(self, hdr):
        """
        session_id = hdr[0:16]
        paylod_md5 = hdr[16:32]

        n = hdr[32]
        action = n & 0x0f
        tot_len = (hdr[33] << 8) | hdr[34]
        real_size = (hdr[35] << 8) | hdr[36]

        return (session_id, paylod_md5, action, tot_len, real_size,)
        """
        return struct.unpack(_FMT, hdr)

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        size = self.__reader.size()

        if self.__header_ok:
            if size < self.__tot_length: return
            e_body = self.__reader.read(self.__tot_length)
            body = self.unwrap_body(self.__real_length, e_body)

            if proto_utils.calc_content_md5(body) != self.__payload_md5: raise proto_utils.ProtoError(
                "data has been modified")

            self.__results.append((self.__session_id, self.__action, body,))
            self.reset()
            return
        if self.__reader.size() < self.__fixed_hdr_size: return
        hdr = self.unwrap_header(self.__reader.read(self.__fixed_hdr_size))
        if not hdr:
            self.reset()
            return
        self.__session_id, self.__payload_md5, \
        self.__action, self.__tot_length, self.__real_length = self.__parse_header(hdr)
        self.__header_ok = True

    def unwrap_header(self, header):
        """重写这个方法"""
        return header

    def unwrap_body(self, real_size, body_data):
        """重写这个方法"""
        return body_data

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

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass
