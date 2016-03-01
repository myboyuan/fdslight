#!/usr/bin/env python3
import pywind.lib.reader as reader
import random


class WsProtoErr(Exception):
    """websocket协议故障
    """
    pass


class websocket(object):
    """装饰websocket,使其操作更像本地socket"""
    __socket = None

    def __bytes_to_int(self, byte_data):
        size = len(byte_data)
        ret = 0
        for i in range(size):
            ret |= byte_data[i] << ((size - 1 - i) * 8)

        return ret

    def accept(self):
        return self.__socket.accept()

    def listen(self, backlog=0):
        pass

    def bind(self, address):
        self.__socket.bind(address)

    def close(self):
        pass

    def connect(self):
        pass

    def recv(self):
        pass

    def send(self):
        pass

    def setblocking(self, flag):
        self.__socket.setblocking(flag)

    def settimeout(self, value):
        self.__socket.settimeout(value)

    def setsockopt(self, level, optname, value):
        self.__socket.setsockopt(optname, value)

    def getsockopt(self):
        pass

    def getpeernname(self):
        pass

    def recv_into(self):
        pass

    def makefile(self):
        pass

    def fileno(self):
        return self.__socket.fileno()

    def sendall(self):
        pass

    def shutdown(self):
        pass


class wrap_socket(object):
    def __init__(self, s, server_side=False):
        pass
