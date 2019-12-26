#!/usr/bin/env python3

import pywind.lib.reader as reader
import struct, socket

TYPE_WAKEUP_REQ = 1
TYPE_WAKEUP_RESP = 2

TYPES = (
    TYPE_WAKEUP_REQ, TYPE_WAKEUP_RESP,
)


class wake_on_lan(object):
    """用来唤醒局域网的机器
    """
    __s = None

    def __init__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.__s = s

    def wake(self, dst_mac):
        magic_pkt = self.__gen_magic_packet(dst_mac)
        if not magic_pkt: return

        self.__s.sendto(magic_pkt, ("255.255.255.255", 7,))

    def __gen_magic_packet(self, hwaddr):
        """生成magic包
        :param hwaddr:
        :return:
        """
        a = [255, 255, 255, 255, 255, 255]
        byte_a = bytes(a)

        a = []
        seq = hwaddr.split(":")

        if len(seq) != 6: return None

        for s in seq:
            v = int("0x%s" % s, 16)
            a.append(v)
        b = bytes(a)
        b = b * 16

        return b"".join([byte_a, b])

    def release(self):
        self.__s.close()


class WOLProtoErr(Exception): pass


def byte2mac(byte_data):
    results = []

    for n in byte_data:
        s = hex(n)
        if len(s) < 4:
            v = "0%s" % s[2:]
        else:
            v = s[2:]

        results.append(v)

    return ":".join(results)


def mac2byte(s):
    a = []
    seq = s.split(":")
    if len(seq) != 6: raise WOLProtoErr("wrong mac address format")
    for s in seq:
        try:
            v = int("0x%s" % s, 16)
        except ValueError:
            return None
        a.append(v)
    b = bytes(a)

    return b


class parser(reader.reader):
    __reader = None
    __results = None
    __header_ok = None
    __length = None
    __type = None

    def __init__(self):
        self.__reader = reader.reader()
        self.__results = []
        self.__header_ok = False

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def __parse_wol_request(self, byte_data):
        if self.__length < 258:
            raise WOLProtoErr("wrong wake up request packet length 1")

        key_length = byte_data[0]
        byte_data = byte_data[1:]
        key = byte_data[0:key_length]
        byte_data = byte_data[255:]

        n = byte_data[0]
        byte_data = byte_data[1:]

        ### 检查是否是6的倍数
        if len(byte_data) != n * 6:
            raise WOLProtoErr("wrong wake up request packet length 2")

        seq = []
        for i in range(n):
            hwaddr = byte2mac(byte_data[0:6])
            seq.append(hwaddr)
            byte_data = byte_data[6:]

        self.__results.append(
            (self.__type, (key.decode(), seq,))
        )

    def __parse_body(self):
        if self.__reader.size() < self.__length: return

        self.__header_ok = False
        data = self.__reader.read(self.__length)

        if self.__type == TYPE_WAKEUP_REQ:
            self.__parse_wol_request(data)
            return

        if self.__length != 4:
            raise WOLProtoErr("wrong wake up response length")

        is_error, = struct.unpack("!i", data)

        self.__results.append(
            (self.__type, is_error,)
        )

    def __parse_header(self):
        if self.__reader.size() < 4: return
        self.__type, _, self.__length = struct.unpack("!BBH", self.__reader.read(4))
        self.__header_ok = True
        if self.__type not in TYPES:
            raise WOLProtoErr("wrong protocol number %s" % self.__type)

    def parse(self):
        if not self.__header_ok:
            self.__parse_header()
        if self.__header_ok:
            self.__parse_body()

    def get_result(self):
        result = None
        try:
            result = self.__results.pop(0)
        except IndexError:
            pass

        return result


class builder(object):
    def build_data(self, _type, byte_data):
        length = len(byte_data)
        header = struct.pack("!BBH", _type, 0, length)

        return b"".join([header, byte_data])

    def build_request(self, key, hwaddrs=[]):
        byte_key = key.encode()
        k_len = len(byte_key)
        if k_len > 0xff: raise WOLProtoErr("wrong key length")
        n_mac = len(hwaddrs)

        byte_key = byte_key + b"\0" * (255 - k_len)

        seq = []
        seq.append(struct.pack("!B", k_len))
        seq.append(byte_key)
        seq.append(struct.pack("!B", n_mac))

        for s in hwaddrs:
            byte_mac = mac2byte(s)
            seq.append(byte_mac)

        return self.build_data(TYPE_WAKEUP_REQ, b"".join(seq))

    def build_response(self, is_error=0):
        byte_data = struct.pack("!i", is_error)

        return self.build_data(TYPE_WAKEUP_RESP, byte_data)


"""
b = builder()
#data = b.build_request("hello", hwaddrs=["98:F2:B3:F0:4A:18","98:F2:B3:F0:4A:18"])
data=b.build_response()
print(data)
p = parser()
p.input(data)
p.parse()
print(p.get_result())
"""
