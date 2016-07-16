#!/usr/bin/env python3
import pywind.lib.reader as reader


class MultipartErr(Exception): pass


class builder(object):
    pass


class parser(object):
    __begin = None
    __end = None

    __begin_size = 0
    __end_size = 0

    __is_start = False
    __reader = None

    __all_ok = False
    __single_ok = False
    __data_list = None

    def __init__(self, fdst, boundary):
        self.__begin = ("--%s\r\n" % boundary).encode()
        self.__end = ("--%s--\r\n" % boundary).encode()

        self.__begin_size = len(self.__begin)
        self.__end_size = len(self.__end)

        self.__data_list = []
        self.__reader = fdst

    def __parse_part_header(self):
        SIZE = 4096
        line = self.__reader.readline(SIZE)
        is_file, name, filename = self.__get_disposition(line)
        content_type = None

        if is_file:
            line = self.__reader.readline(SIZE)
            content_type = self.__get_content_type(line)
        line = self.__reader.readline(2)
        if line != b"\r\n": raise MultipartErr("wrong part header")

        return {"is_file": is_file, "name": name, "filename": filename, "content_type": content_type,}

    def __get_content_type(self, byte_data):
        try:
            sts = byte_data.decode()
        except UnicodeDecodeError:
            raise MultipartErr("wrong part header")
        if sts[0:13].lower() != "content-type:": raise MultipartErr("wrong part header")
        sts = sts[13:].lstrip()

        return sts[0:-2]

    def __get_disposition(self, byte_data):
        try:
            sts = byte_data.decode()
        except UnicodeDecodeError:
            raise MultipartErr("wrong part header")
        sts = sts[0:-2]
        if sts[0:20].lower() != "content-disposition:": raise MultipartErr("wrong part header")
        sts = sts[20:].lstrip()
        if sts[0:10] != "form-data;": raise MultipartErr("wrong content-disposition format")
        sts = sts[10:].lstrip()
        if sts[0:5] != "name=": raise MultipartErr("wrong content-disposition format")
        sts = sts[5:]

        is_file = False
        name = self.__get_quotation_mark_content(sts)
        n = len(name) + 2
        sts = sts[n:].lstrip()

        if sts:
            if len(sts) < 4 or sts[0] != ";": raise MultipartErr("wrong content-disposition format")
            sts = sts[1:].lstrip()
            if sts[0:9] != "filename=": raise MultipartErr("wrong content-disposition format")
        if sts and sts[0:9] == "filename=": is_file = True

        if not is_file: return (is_file, name, None,)
        sts = sts[9:]
        filename = self.__get_quotation_mark_content(sts)
        n = len(filename) + 2
        if sts[n:]: raise MultipartErr("wrong content-disposition format")

        return (is_file, name, filename,)

    def __get_quotation_mark_content(self, s):
        """提取引号里面的内容"""
        seq = []
        is_first = True
        have_end_mark = False
        for ch in s:
            if is_first and ch != "\"": raise MultipartErr("wrong content-disposition format")
            if ch == "\"" and is_first:
                is_first = False
                continue
            if ch == "\"":
                have_end_mark = True
                break
            seq.append(ch)
        if not have_end_mark: raise MultipartErr("wrong content-disposition format")
        return "".join(seq)

    def parse(self):
        if self.__all_ok: return
        line = self.__reader.readline(self.__end_size)
        if not line: raise MultipartErr("multipart format error")
        if line == self.__begin or line == self.__end:
            if line == self.__end: self.__all_ok = True
            if self.__is_start: self.__single_ok = True
            return
        self.__data_list.append(line)

    def single_ok(self):
        return self.__single_ok

    def reset(self):
        self.__single_ok = False

    def all_ok(self):
        return self.__all_ok

    def get_info(self):
        """获取单个part的信息"""
        if not self.__is_start:
            line = self.__reader.readline(self.__end_size)
            if not self.__is_start and len(line) < self.__begin_size: raise MultipartErr("multipart format error")
            if not self.__is_start and line != self.__begin: raise MultipartErr("multipart format error")
        self.__is_start = True
        return self.__parse_part_header()

    def get_part_data(self):
        """获取单个part的数据"""
        tmplist = []
        if len(self.__data_list) == 1:
            if self.single_ok():
                return self.__data_list.pop(0)
            else:
                return b""
        while 1:
            try:
                tmplist.append(self.__data_list.pop(0))
            except IndexError:
                break
        return b"".join(tmplist)

"""
fd = open("./test.txt", "rb")
cls = parser(fd, "----WebKitFormBoundaryrGKCBY7qhFd3TrwA")

is_get_hdr = False
while 1:
    if cls.all_ok(): break
    if not cls.single_ok() and not is_get_hdr:
        is_get_hdr = True
        print(cls.get_info())
    if is_get_hdr and not cls.single_ok():
        cls.parse()
        # 去除结尾的\r\n
        if cls.single_ok():
            is_get_hdr = False
            print(cls.get_part_data()[0:-2])
            cls.reset()
        else:
            print(cls.get_part_data())
fd.close()
"""