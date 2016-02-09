#!/usr/bin/env python3
import freenet.lib.base_proto.exception as exception
import pywind.lib.reader as reader

"""基本帧协议
version:4bit 协议版本,目前为1
action:4 bit 动作类型
data_length:2 bytes 数据长度
real_length:2 bytes 指的是加密前的数据长度
"""

###动作部分
# 表示这是一个ping
ACT_PING = 1
# 表示这是一个pong
ACT_PONG = 2
# 表示一个会话验证
ACT_AUTH = 3
# 表示这是数据包
ACT_DATA = 4
# 表示关闭
ACT_CLOSE = 5

# 传输协议最小所占用的头大小
PROTO_MIN_HEADER_SIZE = 5

MAX_BODY_SIZE = 65535


class over_tcp_builder(object):
    __acts = [
        ACT_AUTH,
        ACT_PING,
        ACT_PONG,
        ACT_DATA,
        ACT_CLOSE
    ]

    __fixed_header_size = PROTO_MIN_HEADER_SIZE

    def __init__(self, fixed_header_size):
        self.__fixed_header_size = fixed_header_size

    def build_proto_header(self, real_size, body_size, action):
        """
        :param body_size: 内容体数据
        :return:
        """
        if action not in self.__acts:
            raise exception.ProtocolErr("it is wrong action")
        L = (
            (1 << 4) | action,
            (body_size & 0xff00) >> 8,
            body_size & 0x00ff,
            (real_size & 0xff00) >> 8,
            real_size & 0x00ff
        )

        return bytes(L)

    def wrap_body(self, body):
        pass

    def wrap_header(self, body_size, action):
        pass

    def reset(self):
        """重写这个方法
        :return:
        """
        pass

    def build_pong(self):
        """重写这个方法,构建ping帧
        :return:
        """
        pass

    def build_ping(self):
        """重写这个方法,构建pong帧
        :return:
        """
        pass

    def build_close(self):
        """重写这个方法,构建close帧
        :return:
        """
        pass

    def set_body_size(self, body_size):
        """重写这个方法,不同的加密协议可能有不同的body_size要求
        :param body_size:
        :return:
        """
        pass

    def fixed_header_size(self):
        return self.__fixed_header_size


class over_tcp_parser(object):
    __reader = reader.reader()
    __body_size = 0

    __header_ok = False
    __header_info = None
    __fixed_header_size = -1
    __real_size = 0

    def __init__(self, fixed_header_size):
        self.__fixed_header_size = fixed_header_size

    def add_data(self, byte_data):
        self.__reader._putvalue(byte_data)

    def __header_parse(self):
        if self.__reader.size() < self.__fixed_header_size:
            return None

        header = self.unwrap_header(self.__reader.read(self.__fixed_header_size))

        if not header:
            return None

        n = header[0]
        version = (n & 0xf0) >> 4
        action = n & 0x0f

        data_length = (header[1] << 8) | header[2]
        real_length = (header[3] << 8) | header[4]

        self.__body_size = data_length
        self.__header_ok = True
        self.__header_info = action
        self.__real_size = real_length

    @property
    def real_size(self):
        return self.__real_size

    def body_data(self):
        buff_size = self.__reader.size()

        if buff_size < self.__body_size:
            return b""

        body = self.__reader.read(self.__body_size)

        return self.unwrap_body(body)

    def reset(self):
        self.__body_size = 0
        self.__header_ok = False
        self.__header_info = None
        self.__real_size = 0

    def unwrap_header(self, header):
        """重写这个方法
        :param header:
        :return new_header:
        """
        return header

    def unwrap_body(self, body):
        """重写这个方法
        :param body:
        :return new_body:返回新的body
        """
        return body

    def header_info(self):
        return self.__header_info

    def is_ok(self):
        if not self.__header_ok:
            self.__header_parse()

        if self.__header_ok and self.__reader.size() >= self.__body_size:
            return True

        return False

    def have_data(self):
        """检查是否还有数据"""
        return self.__reader.size() != 0
