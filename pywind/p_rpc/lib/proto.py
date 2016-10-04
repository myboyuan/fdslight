#!/usr/bin/env python3
### socket协议,用于承载RPC数据
"""协议如下
direction:1 byte , 0表示请求,1表示响应
is_first: 1 byte  , 1表示是第一次请求或者响应,0表示并非第一次请求或者响应
content_length:2 byte , 数据内容长度
"""

import pywind.lib.reader as reader


class builder(object):
    def __init__(self):
        pass

    def __build(self, direction, sts, is_first=False):
        seq = []
        if direction:
            seq.append(0)
        else:
            seq.append(1)
        if is_first:
            seq.append(1)
        else:
            seq.append(0)

        byte_data = sts.encode()
        size = len(byte_data)
        seq += [
            (size & 0xff00) >> 8,
            size & 0xff
        ]

        return b"".join([bytes(seq), byte_data, ])

    def build_request(self, sts, is_first=False):
        return self.__build(0, sts, is_first)

    def build_response(self, sts, is_first=False):
        return self.__build(1, sts, is_first)


class parser(object):
    __reader = None
    __direction = 0
    __is_first = 0
    __result = None

    def __init__(self):
        self.__reader = reader.reader()

    def parse(self):
        self.__result = None
        if self.__reader.size() < 4: return False
        rdata = self.__reader.read(4)
        direction = rdata[0]
        is_first = rdata[1]
        length = (rdata[2] << 8) | rdata[3]

        if self.__reader.size() < length: self.__reader.push(rdata)

        self.__direction = direction
        self.__is_first = bool(is_first)
        self.__result = self.__reader.read(length).decode()

        return True

    def is_first(self):
        return self.__is_first

    @property
    def direction(self):
        return self.__direction

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def get_result(self):
        return self.__result
