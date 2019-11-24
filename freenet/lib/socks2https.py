#!/usr/bin/env python3
import pywind.lib.reader as reader

import struct, socket

HEADER_FMT = "!BBH"

FRAME_TYPE_PING = 0
FRAME_TYPE_PONG = 1
FRAME_TYPE_TCP_CONN = 2
FRAME_TYPE_UDP_CONN = 4
FRAME_TYPE_UDPLite_CONN = 5
FRAME_TYPE_CONN_STATE = 6
FRAME_TYPE_TCP_DATA = 7
FRAME_TYPE_UDP_DATA = 9
FRAME_TYPE_UDPLITE_DATA = 10

frame_types = (
    FRAME_TYPE_PING, FRAME_TYPE_PONG,
    FRAME_TYPE_TCP_CONN, FRAME_TYPE_UDP_CONN,
    FRAME_TYPE_UDPLite_CONN, FRAME_TYPE_CONN_STATE,
    FRAME_TYPE_TCP_DATA, FRAME_TYPE_UDP_DATA,
    FRAME_TYPE_UDPLITE_DATA,
)

ADDR_TYPE_IP = 0
ADDR_TYPE_IPv6 = 1
ADDR_TYPE_DOMAIN = 2
ADDR_TYPE_FORCE_DOMAIN_IPv6 = 3

addr_types = (
    ADDR_TYPE_IP, ADDR_TYPE_IPv6, ADDR_TYPE_DOMAIN, ADDR_TYPE_FORCE_DOMAIN_IPv6,
)

CONN_STATE_FMT = "!Ii"
CONN_FMT = "!IHBB"


class FrameError(Exception): pass


class parser(object):
    __reader = None
    __content_length = None
    __is_parsed_header = None
    __results = None
    __frame_type = None

    def __init__(self):
        self.__reader = reader.reader()
        self.__content_length = 0
        self.__is_parsed_header = False
        self.__results = []

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse_header(self):
        if self.__reader.size() < 4: return
        _, self.__frame_type, self.__content_length = struct.unpack("!BBH", self.__reader.read(4))
        self.__is_parsed_header = True

    def handle_conn_frame(self, byte_data):
        length = len(byte_data)
        if length < 9:
            raise FrameError("wrong connection frame format for type %s" % self.__frame_type)

        _id, port, addr_type, addr_length, = struct.unpack(CONN_FMT, byte_data[0:8])
        byte_data = byte_data[8:]
        length = length - 8

        if addr_length == 0:
            raise FrameError("wrong connection frame addr length,it should not be zero")

        if addr_length > length:
            raise FrameError("wrong connection frame length")

        if addr_type not in addr_types:
            raise FrameError("wrong connection frame addr type %s" % addr_type)

        if addr_type == ADDR_TYPE_IP and addr_length != 4:
            raise FrameError("wrong connection frame addr_length for ip")

        if addr_type == ADDR_TYPE_IPv6 and addr_length != 16:
            raise FrameError("wrong connection frame addr_length for ipv6")

        if addr_type == ADDR_TYPE_IP:
            address = socket.inet_ntop(socket.AF_INET, byte_data[0:4])
        elif addr_type == ADDR_TYPE_IPv6:
            address = socket.inet_ntop(socket.AF_INET6, byte_data[0:16])
        else:
            address = byte_data[0:addr_length].decode("iso-8859-1")
        byte_data = byte_data[addr_length:]
        self.__results.append(
            (
                self.__frame_type,
                (_id, address, port, addr_type, byte_data,),
            )
        )

    def handle_conn_state_frame(self, byte_data):
        if len(byte_data) != 8:
            raise FrameError("wrong tcp connection frame length")

        _id, err_code = struct.unpack(CONN_STATE_FMT, byte_data)
        self.__results.append(
            (
                self.__frame_type,
                (_id, err_code,)
            )
        )

    def handle_tcp_data_frame(self, byte_data):
        if len(byte_data) < 9:
            raise FrameError("wrong tcp data frame length")

        _id, win_size, reverse = struct.unpack("!IHH", byte_data[0:8])
        self.__results.append(
            (
                self.__frame_type,
                (_id, win_size, byte_data[8:])
            )
        )

    def handle_ping_and_pong_frame(self):
        self.__results.append(
            (
                self.__frame_type,
                (None,)
            )
        )

    def parse_body(self):
        body_data = self.__reader.read(self.__content_length)
        self.__is_parsed_header = False
        if self.__frame_type not in frame_types:
            raise FrameError("unsupport data frame type %s" % self.__frame_type)

        conn_frames = (
            FRAME_TYPE_TCP_CONN, FRAME_TYPE_UDP_CONN, FRAME_TYPE_UDPLite_CONN,
            FRAME_TYPE_UDP_DATA, FRAME_TYPE_UDPLITE_DATA,
        )

        if self.__frame_type in conn_frames:
            self.handle_conn_frame(body_data)
            return

        if self.__frame_type == FRAME_TYPE_CONN_STATE:
            self.handle_conn_state_frame(body_data)
            return

        if self.__frame_type == FRAME_TYPE_TCP_DATA:
            self.handle_tcp_data_frame(body_data)
            return

        if self.__frame_type in (FRAME_TYPE_PING, FRAME_TYPE_PONG,):
            self.handle_ping_and_pong_frame()
            return

    def parse(self):
        if not self.__is_parsed_header:
            self.parse_header()

        if not self.__is_parsed_header: return
        if self.__reader.size() >= self.__content_length: self.parse_body()

    def get_result(self):
        rs = None
        try:
            rs = self.__results.pop(0)
        except IndexError:
            pass
        return rs


class builder(object):
    def __init__(self):
        pass

    def build_header(self, frame_type, length):
        return struct.pack(HEADER_FMT, 1, frame_type, length)

    def build_frame(self, frame_type, byte_data):
        length = len(byte_data)
        header = self.build_header(frame_type, length)

        return b"".join([header, byte_data])

    def build_ping(self, byte_data=b""):
        return self.build_frame(FRAME_TYPE_PING, byte_data)

    def build_pong(self, byte_data=b""):
        return self.build_frame(FRAME_TYPE_PONG, byte_data)

    def build_conn_frame(self, frame_type, packet_id, addr_type, address, port, byte_data=b""):
        """ TCP连接和UDP,UDPLite的数据帧
        :param frame_type:
        :param packet_id:
        :param addr_type:
        :param address:
        :param port:
        :param byte_data:
        :return:
        """
        addr_len = 0
        conn_frames = (
            FRAME_TYPE_TCP_CONN, FRAME_TYPE_UDP_CONN, FRAME_TYPE_UDPLite_CONN,
            FRAME_TYPE_UDP_DATA, FRAME_TYPE_UDPLITE_DATA,
        )

        if frame_type not in conn_frames:
            raise ValueError("wrong argument value because of argument frame_type")

        if addr_type not in addr_types:
            raise ValueError("wrong addr_type argumnet")

        if addr_type == ADDR_TYPE_IP:
            byte_addr = socket.inet_pton(socket.AF_INET, address)
        elif addr_type == ADDR_TYPE_IPv6:
            byte_addr = socket.inet_pton(socket.AF_INET6, address)
        else:
            byte_addr = address.encode("iso-8859-1")

        addr_len = len(byte_addr)
        a = struct.pack(CONN_FMT, packet_id, port, addr_type, addr_len)
        b = b"".join([a, byte_addr, byte_data])

        return self.build_frame(frame_type, b)

    def build_conn_state(self, packet_id, err_code=0):
        a = struct.pack(CONN_STATE_FMT, packet_id, err_code)

        return self.build_frame(FRAME_TYPE_CONN_STATE, a)

    def build_tcp_frame_data(self, packet_id, data, win_size=1200):
        a = struct.pack("!IHH", packet_id, win_size, 0)
        b = b"".join([a, data])

        return self.build_frame(FRAME_TYPE_TCP_DATA, b)


class qos(object):
    __qos = None

    def __init__(self):
        self.__qos = {}

    def input(self, packet_id, byte_data):
        if packet_id not in self.__qos:
            self.__qos[packet_id] = []
        seq = self.__qos[packet_id]
        seq.append(byte_data)

    def get_data(self):
        dels = []
        results = []

        for k, v in self.__qos.items():
            if not v:
                dels.append(k)
                continue
            results.append(v.pop(0))

        for _id in dels:
            del self.__qos[_id]

        return results

    def have_data(self):
        return bool(self.__qos)


"""
p = parser()
b = builder()

data = b.build_conn_frame(FRAME_TYPE_UDP_DATA, 1000, ADDR_TYPE_IP, "192.168.1.1", 6800, byte_data=b"hello")
p.input(data)
data = b.build_pong()
p.input(data)

while 1:
    p.parse()
    rs=p.get_result()
    if not rs:break
    print(rs)
"""
