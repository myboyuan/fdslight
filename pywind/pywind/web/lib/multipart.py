#!/usr/bin/env python3
"""处理HTTP multipart"""


class MultipartError(Exception):
    pass


class multipart_block(object):
    """单个block对象"""
    # 内容起始位置
    __begin_p = 0
    # 内容的结束位置
    __end_p = 0
    # 是否是文件块
    __file = None

    ### 以下属性如果不是文件默认为None
    # 内容类型
    __content_type = None
    # 文件名
    __filename = None

    def __init__(self, begin_p, end_p, fp, filename=None, content_type=None):
        """
        :param begin_p:内容开始位置
        :param end_p: 内容结束为止
        :param fp:文件对象
        :return:
        """
        self.__begin_p = begin_p
        self.__end_p = end_p
        self.__file = fp
        self.__filename = filename
        self.__content_type = content_type

    def read(self, n=-1):
        self.__file.seek(self.__begin_p)
        size = self.size()
        if n == -1 or n > size: n = size

        return self.__file.read(n)

    def size(self):
        return self.__end_p - self.__begin_p

    @property
    def content_type(self):
        return self.__content_type

    @property
    def filename(self):
        return self.__filename


class builder(object):
    pass


class parser(object):
    __begin_boundary = None
    __end_boundary = None

    __part_is_start = False
    __part_is_eof = False

    __begin_pos = None
    __end_pos = None

    # 内容类型,如果不是文件则为空
    __content_type = None
    # 文件名,如果没有则为空
    __filename = None

    __file = None

    # 所有的块是否都结束
    __is_eof = False

    # 表单域名
    __name = ""

    def __init__(self, boundary, fp):
        """
        :param boundary: 边界
        :param fp: 文件对象
        :return:
        """
        begin = "--%s\r\n" % boundary
        end = "--%s--\r\n" % boundary

        self.__begin_boundary = begin.encode("iso-8859-1")
        self.__end_boundary = end.encode("iso-8859-1")
        self.__file = fp

    def __handle_block_header(self):
        """处理单个内容块的块头"""
        line = self.__file.readline()
        is_file, name, filename = self.__get_content_position(line)

        if not is_file:
            self.__file.readline()
            self.__begin_pos = self.__file.tell()
            return
        line = self.__file.readline()
        content_type = self.__get_file_content_type(line)

        self.__content_type = content_type
        self.__filename = filename
        self.__name = name
        self.__file.readline()

    def parse(self):
        if self.__is_eof: return
        if self.__part_is_eof: return

        line = self.__file.readline()

        if not self.__part_is_start and line != self.__begin_boundary:
            raise MultipartError("the multipart first line is not begin boundary")

        if line == self.__end_boundary and not self.__part_is_start:
            raise MultipartError("there is not begin boundary but it has end boundary")

        if line == self.__begin_boundary:
            if self.__part_is_start:
                self.__part_is_eof = True
                return
            self.__handle_block_header()
            self.__part_is_start = True

        if line == self.__end_boundary:
            self.__is_eof = True
            return

        line = self.__file.readline()
        if self.__part_is_start and line != self.__begin_boundary:
            self.__end_pos = self.__file.tell()
        return

    def __get_content_position(self, bin_data):
        is_file = False
        sts = bin_data.decode()
        sts = sts[0:-2]
        if sts[19] != ":":
            raise MultipartError
        sts = sts[20:].lstrip()
        sts = sts[10:]
        sts = sts.lstrip()
        if sts[0:5] != "name=":
            raise MultipartError
        sts = sts[5:]
        pos = sts.find(";")
        # 表单域格式不正确
        if pos < 2:
            raise MultipartError
        # 如果pos<0说明不是文件区域
        if pos < 0:
            name = sts[1:-1]
            return (is_file, name, None)
        n = pos - 1
        name = sts[1:n]
        n = pos + 1
        sts = sts[n:].lstrip()
        if sts[0:9] != "filename=":
            raise MultipartError
        sts = sts[9:]
        return (True, name, sts[1:-1])

    def __get_file_content_type(self, bin_data):
        """获取文件内容类型"""
        sts = bin_data.decode()
        sts = sts[0:-2]
        if sts[0:13].lower() != "content-type:":
            raise MultipartError
        sts = sts[13:].lstrip()

        return sts

    def __reset(self):
        self.__part_is_start = False
        self.__part_is_eof = False
        self.__begin_pos = 0
        self.__end_pos = 0
        self.__content_type = None
        self.__filename = None
        self.__name = ""

    def part_is_eof(self):
        return self.__part_is_eof

    def is_eof(self):
        return self.__is_eof

    def get_multipart_block(self):
        b = multipart_block(self.__begin_pos,
                            self.__end_pos - 2,
                            None,
                            self.__filename,
                            self.__content_type
                            )
        name = self.__name
        self.__reset()
        return (name, b)
