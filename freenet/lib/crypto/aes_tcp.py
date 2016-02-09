#!/usr/bin/env python3
"""
AES加密模块
"""
"""
import sys
sys.path.append("../../../")
"""
import freenet.lib.base_proto.over_tcp as over_tcp
import random
from Crypto.Cipher import AES

_AES_FIXED_HEADER_SIZE = 32


class encrypt(over_tcp.over_tcp_builder):
    __max_body_size = 4096

    # 需要补充的`\0`
    __const_fill_nuls = b""
    __key = b"0123456789123456"
    __iv = b""

    # 加密后的数据包长度
    __body_size = 0
    # 真正数据的长度
    __real_size = 0

    def __init__(self):
        super(encrypt, self).__init__(_AES_FIXED_HEADER_SIZE)
        # 预先计算好一些数值,可以加快速度
        self.__max_body_size = int(over_tcp.MAX_BODY_SIZE / 16) * 16

        if over_tcp.PROTO_MIN_HEADER_SIZE % 16 != 0:
            self.__const_fill_nuls = b"\0" * (16 - over_tcp.PROTO_MIN_HEADER_SIZE % 16)

        return

    def __rand(self, length=16):
        sset = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        seq = []

        for i in range(length):
            n = random.randint(0, 61)
            seq.append(sset[n])

        return "".join(seq).encode("iso-8859-1")

    def build_ping(self):
        return self.wrap_header(over_tcp.ACT_PING)

    def build_pong(self):
        return self.wrap_header(over_tcp.ACT_PONG)

    def build_close(self):
        return self.wrap_header(over_tcp.ACT_CLOSE)

    def wrap_body(self, body):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        fill = b"\0" * (self.__body_size - self.__real_size)
        data = body + fill

        return cipher.encrypt(data)

    def wrap_header(self, action):
        iv = self.__rand()
        hdr_part = self.build_proto_header(self.__real_size, self.__body_size, action)
        cipher = AES.new(self.__key, AES.MODE_CFB, iv)
        self.__iv = iv
        seq = [
            hdr_part,
            self.__const_fill_nuls
        ]

        e_data = cipher.encrypt(b"".join(seq))

        return iv + e_data

    def set_body_size(self, body_size):
        a = body_size % 16
        if a:
            r = (int(body_size / 16) + 1) * 16
        else:
            r = body_size

        self.__real_size = body_size
        self.__body_size = r

    def reset(self):
        super(encrypt, self).reset()
        self.__body_size = 0
        self.__real_size = 0

    def set_aes_key(self, key):
        if len(key)!=16:
            raise ValueError("the size of key must be 16")
        self.__key = key


class decrypt(over_tcp.over_tcp_parser):
    __key = b"0123456789123456"
    __iv = b""
    # 向量字节的开始位置
    __iv_begin_pos = 0
    # 向量字节的结束位置
    __iv_end_pos = 0

    def __init__(self):
        super(decrypt, self).__init__(_AES_FIXED_HEADER_SIZE)
        self.__iv_begin_pos = 0
        self.__iv_end_pos = self.__iv_begin_pos + 16

    def unwrap_header(self, header):
        self.__iv = header[self.__iv_begin_pos:self.__iv_end_pos]
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)

        return cipher.decrypt(header[self.__iv_end_pos:_AES_FIXED_HEADER_SIZE])

    def unwrap_body(self, body):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        d = cipher.decrypt(body)
        real_size = self.real_size

        return d[0:real_size]

    def reset(self):
        super(decrypt, self).reset()

    def set_aes_key(self, key):
        if len(key)!=16:
            raise ValueError("the size of key must be 16")
        self.__key = key

"""
key = b"1234567890123456"
builder = encrypt()
builder.set_aes_key(key)
edata = builder.build_ping()

parser = decrypt()
parser.set_aes_key(key)
parser.add_data(edata)
print(parser.is_ok())
print(parser.body_data())
"""