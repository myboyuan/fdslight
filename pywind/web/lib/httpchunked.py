#!/usr/bin/env python3
import pywind.lib.reader as reader


class chunkedErr(Exception): pass


class parser(object):
    __reader = None
    __is_ok = False
    __results = None
    __chunk_size = 0
    __is_start = False
    MAX_MEM_SIZE = 16 * 1024 * 1024

    def __init__(self):
        self.__reader = reader.reader()
        self.__results = []

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        if not self.__is_start:
            sts = self.__reader.readline(10)
            pos = sts.find(b"\r\n")
            if pos < 1 and len(sts) == 10: raise chunkedErr("wrong chunked length:%s" % sts.decode())
            if pos < 1:
                self.__reader._putvalue(sts)
                return
            sts = "0x%s" % sts
            try:
                self.__chunk_size = int(sts, 16)
            except ValueError:
                raise chunkedErr("wrong chunked length:%s" % sts.decode())
            self.__is_start = True

        if self.__reader.size() < self.__chunk_size + 2: return
        byte_data = self.__reader.read(self.__chunk_size + 2)
        self.__results.append(byte_data[0:-2])
        self.__reset()
        self.parse()

    def is_ok(self):
        return self.__is_ok

    def get_chunk(self):
        try:
            return self.__results.pop(0)
        except IndexError:
            return None

    def get_chunk_with_length(self):
        chunk_data = self.get_chunk()
        if not chunk_data: return None
        size = len(chunk_data)
        sts = "%s\r\n" % hex(size)[2:]

        return b"".join(
            (
                sts.encode(),
                chunk_data,
                b"\r\n",
            )
        )

    def __reset(self):
        self.__is_start = False

    def __del__(self):
        self.__reader.flush()
