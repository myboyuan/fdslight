#!/usr/bin/env python3
import pywind.web.lib.httputils as httputils
import pywind.lib.reader as reader
import socket, random


class ws_handshakeErr(Exception): pass


class ws_wantWriteErr(Exception): pass


class ws_wantReadErr(Exception): pass


class ws_serverNotSupportErr(Exception): pass


def _codec_data(mask_key, byte_data):
    seq = []
    for ch in byte_data:
        n = ch % 4
        seq.append(ch ^ mask_key[n])
    return seq


class encoder(object):
    slice_size = 4 * 1024
    rsv = 0
    opcode = 0x2

    __server_side = None

    def __init__(self, server_side=False):
        self.__server_side = server_side

    def __gen_mask_key(self):
        sts = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPQASDFGHJKLZXCVBNM"
        m = len(sts) - 1
        seq = []

        for i in range(4):
            n = random.randint(0, m)
            seq.append(sts[n])

        return "".join(seq).encode("iso-8859-1")

    def __get_ws_frame(self, fin, opcode, byte_data):
        seq = [
            ((fin & 0x1) << 7) | ((self.rsv & 0x7) << 4) | (opcode & 0xf),
        ]
        size = len(byte_data)
        mask_key = None
        if self.__server_side:
            mask = 0
        else:
            mask = 1
            mask_key = self.__gen_mask_key()
        if size < 126:
            payload = size
        elif size < 0x10000:
            payload = 126
        else:
            payload = 127
        seq.append(mask | payload)
        if mask: seq += list(mask_key)
        if mask: seq += _codec_data(mask_key, byte_data)

        return bytes(seq)

    def get_sent_data(self, byte_data):
        """获取发送数据"""
        seq = []
        data_len = len(byte_data)
        b, e = (0, self.slice_size,)

        while b < data_len:
            seq.append(byte_data[b:e])
            b, e = (e, e + self.slice_size,)

        results = []
        bufsize = 0

        for data in seq:
            wrap_data = self.__get_ws_frame(0, 0, data)
            results.append(wrap_data)
            bufsize += len(wrap_data)

        return (bufsize, b"".join(results),)


class decoder(object):
    __reader = None
    # 每个帧的最大数据大小
    max_payload_size = 2 * 1024 * 1024

    __payload = 0
    __read_size = 0
    __fin = 0

    def __init__(self, server_side=False):
        self.__reader = reader.reader()

    def __parse(self):
        seq = []
        while self.__reader.size() > 2:
            backup_seq = []
            n = ord(self.__reader.read(1))
            backup_seq.append(n)
            fin = (n & 0x80) >> 7
            rsv = (n & 0x70) >> 4
            n = ord(self.__reader.read(1))
            backup_seq.append(n)
            mask = (n & 0x80) >> 7
            payload = n & 0x7f

        return seq

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def get_data(self):
        pass

    def is_frame_finish(self):
        """单个数据帧是否结束"""
        return self.__read_size == self.__read_size

    def is_all_finish(self):
        """所有的分帧数据是否结束"""
        return self.__fin


class wrap_socket(object):
    __SLICE_SIZE = 4 * 1024
    __encoder = None
    __decoder = None
    # 是否进行了握手
    __is_handshake = False
    __is_do_handshake = False

    SERVER_NAME = "WSServer"

    __socket = None
    __tmp_buff = None

    def __init__(self, s, server_side=False, do_handshake=False):
        self.__is_do_handshake = do_handshake

        self.__encoder = encoder(server_side=server_side)
        self.__decoder = decoder(server_side=server_side)

        self.__socket = socket.socket()
        self.__tmp_buff = []

    def get_handshake_requestInfo(self):
        """获取握手请求信息"""
        pass

    def bind(self, address):
        return self.__socket.bind(address)

    def connect(self, address):
        return self.__socket.connect(address)

    def accept(self):
        return self.__socket.accept()

    def listen(self, *args, **kwargs):
        return self.__socket.listen(*args, **kwargs)

    @property
    def encoder(self):
        return self.__encoder

    @property
    def decoder(self):
        return self.__decoder

    def send(self, data, *args, **kwargs):
        bufsize, sent_data = self.__encoder.get_sent_data(data)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)

        return self.__socket.send(data, *args, **kwargs)

    def recv(self, bufsize, *args, **kwargs):
        recv_data = self.__socket.recv(bufsize, *args, **kwargs)

        return recv_data

    def response_handshake(self):
        self.__is_handshake = True

    def set_handshake_response(self, status, fields):
        pass

    def set_handshake_request(self, uri, fields):
        pass

    def setsockopt(self, *args, **kwargs):
        return self.__socket.setsockopt(*args, **kwargs)

    def close(self):
        return self.__socket.close()

    def detach(self):
        return self.__socket.detach()

    def fileno(self):
        return self.__socket.fileno()

    def getpeername(self):
        return self.__socket.getpeername()

    def getsockname(self):
        return self.__socket.getsockname()

    def getsockopt(self, *args, **kwargs):
        return self.__socket.getsockopt(*args, **kwargs)

    def gettimeout(self):
        return self.__socket.gettimeout()

    def settimeout(self, timeout):
        return self.__socket.settimeout(timeout)

    def setblocking(self, flag):
        return self.__socket.setblocking(flag)

    def recv_into(self, *args, **kwargs):
        return self.__socket.recv_into(*args, **kwargs)

    def sendall(self, data, *args, **kwargs):
        bufsize, sent_data = self.__encoder.get_sent_data(data)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)

        return self.__socket.sendall(sent_data, *args, **kwargs)

    def shutdown(self, flag):
        return self.__socket.shutdown(flag)
