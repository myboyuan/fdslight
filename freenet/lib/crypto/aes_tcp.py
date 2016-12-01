#!/usr/bin/env python3
"""TCP版本的AES加密模块"""
"""
import sys
sys.path.append("../../../")
"""

from Crypto.Cipher import AES
import random, hashlib
import freenet.lib.base_proto.tunnel_tcp as tunnel
import freenet.lib.base_proto.utils as proto_utils

FIXED_HEADER_SIZE = 64


class encrypt(tunnel.builder):
    __key = b""
    __iv = b""
    # 需要补充的`\0`
    __const_fill = b""

    def __init__(self):
        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill = b"f" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)

        super(encrypt, self).__init__(FIXED_HEADER_SIZE)

    def __rand(self, length=16):
        sset = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        seq = []

        for i in range(length):
            n = random.randint(0, 61)
            seq.append(sset[n])

        return "".join(seq).encode("iso-8859-1")

    def wrap_header(self, base_hdr):
        iv = self.__rand()
        cipher = AES.new(self.__key, AES.MODE_CFB, iv)
        self.__iv = iv
        seq = [
            base_hdr,
            self.__const_fill
        ]
        e_data = cipher.encrypt(b"".join(seq))

        return iv + e_data

    def wrap_body(self, size, body_data):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        fill = b"\0" * (self.get_payload_length(size) - size)
        data = body_data + fill

        return cipher.encrypt(data)

    def get_payload_length(self, pkt_len):
        a = pkt_len % 16
        if a:
            r = (int(pkt_len / 16) + 1) * 16
        else:
            r = pkt_len

        return r

    def __set_aes_key(self, new_key):
        self.__key = hashlib.md5(new_key.encode()).digest()

    def reset(self):
        super(encrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])


class decrypt(tunnel.parser):
    __key = b""
    __iv = b""
    # 向量字节的开始位置
    __iv_begin_pos = 0
    # 向量字节的结束位置
    __iv_end_pos = 0
    __const_fill = b""

    def __init__(self):
        self.__iv_begin_pos = 0
        self.__iv_end_pos = self.__iv_begin_pos + 16

        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill = b"f" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)
        super(decrypt, self).__init__(FIXED_HEADER_SIZE)

    def unwrap_header(self, header_data):
        self.__iv = header_data[self.__iv_begin_pos:self.__iv_end_pos]
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        data = cipher.decrypt(header_data[self.__iv_end_pos:FIXED_HEADER_SIZE])
        real_hdr = data[0:tunnel.MIN_FIXED_HEADER_SIZE]

        # 丢弃误码的包
        if self.__const_fill != data[tunnel.MIN_FIXED_HEADER_SIZE:]: raise proto_utils.ProtoError("data wrong")

        return real_hdr

    def unwrap_body(self, length, body_data):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        d = cipher.decrypt(body_data)

        return d[0:length]

    def __set_aes_key(self, key):
        new_key = hashlib.md5(key.encode()).digest()
        self.__key = new_key

    def reset(self):
        super(decrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])


"""
key="name"
builder = encrypt()
builder.config({"key":key})

e_rs = builder.build_packet(bytes(16),tunnel.ACT_DATA,b"hello")
builder.reset()

parser = decrypt()
parser.config({"key":"name"})
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())

e_rs = builder.build_packet(bytes(16),tunnel.ACT_DATA,b"world")
builder.reset()
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())
"""