#!/usr/bin/env python3
"""UDP版本的AES加密模块"""

"""
import sys
sys.path.append("../../../")
"""

from Crypto.Cipher import AES
import random, hashlib
import freenet.lib.base_proto.tunnel as tunnel

FIXED_HEADER_SIZE = 32


class encrypt(tunnel.builder):
    __key = b""
    __iv = b""
    # 需要补充的`\0`
    __const_fill_nuls = b""

    __real_size = 0
    __body_size = 0

    def __init__(self, aes_key):
        self.__key = hashlib.md5(aes_key.encode()).digest()

        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill_nuls = b"\0" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)

        super(encrypt, self).__init__(FIXED_HEADER_SIZE)

    def __rand(self, length=16):
        sset = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        seq = []

        for i in range(length):
            n = random.randint(0, 61)
            seq.append(sset[n])

        return "".join(seq).encode("iso-8859-1")

    def build_ping(self):
        pkts = self.build_packets(tunnel.ACT_PING, 0, b"")

        return pkts[0]

    def build_pong(self):
        pkts = self.build_packets(tunnel.ACT_PONG, 0, b"")

        return pkts[0]

    def build_close(self):
        pkts = self.build_packets(tunnel.ACT_CLOSE, 0, b"")

        return pkts[0]

    def wrap_header(self, base_hdr):
        iv = self.__rand()
        cipher = AES.new(self.__key, AES.MODE_CFB, iv)
        self.__iv = iv
        seq = [
            base_hdr,
            self.__const_fill_nuls
        ]
        e_data = cipher.encrypt(b"".join(seq))

        return iv + e_data

    def wrap_body(self, size, body_data):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        fill = b"\0" * (self.__get_body_size(size) - size)
        data = body_data + fill

        return cipher.encrypt(data)

    def get_max_body_size(self):
        return tunnel.EVERY_PKT_SIZE - FIXED_HEADER_SIZE - tunnel.EVERY_PKT_SIZE % 16

    def __get_body_size(self, real_size):
        a = real_size % 16
        if a:
            r = (int(real_size / 16) + 1) * 16
        else:
            r = real_size

        return r

    def set_aes_key(self, new_key):
        self.__key = hashlib.md5(new_key.encode()).digest()

    def reset(self):
        super(encrypt, self).reset()


class decrypt(tunnel.parser):
    __key = b""
    __iv = b""
    # 向量字节的开始位置
    __iv_begin_pos = 0
    # 向量字节的结束位置
    __iv_end_pos = 0

    def __init__(self, aes_key):
        self.__key = hashlib.md5(aes_key.encode()).digest()
        self.__iv_begin_pos = 0
        self.__iv_end_pos = self.__iv_begin_pos + 16
        super(decrypt, self).__init__(FIXED_HEADER_SIZE)

    def unwrap_header(self, header_data):
        self.__iv = header_data[self.__iv_begin_pos:self.__iv_end_pos]
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)

        return cipher.decrypt(header_data[self.__iv_end_pos:FIXED_HEADER_SIZE])

    def unwrap_body(self, length, body_data):
        cipher = AES.new(self.__key, AES.MODE_CFB, self.__iv)
        d = cipher.decrypt(body_data)

        return d[0:length]

    def set_aes_key(self, key):
        new_key = hashlib.md5(key.encode()).digest()
        self.__key = new_key

    def reset(self):
        super(decrypt, self).reset()


"""
data = bytes(800)
size = len(data)

builder = encrypt()
packets = builder.build_packets(tunnel.ACT_DATA, size, data)

parser = decrypt()

for pkt in packets:
    ret = parser.parse(pkt)
    if ret: print(ret, len(ret))
"""
