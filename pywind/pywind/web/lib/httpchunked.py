#!/usr/bin/env python3

import io


class parser(object):
    """
    parse http chunk
    """

    # {size:content,...}
    __data_list = []
    __is_finish = False
    __is_ret_finish_flag = False

    def __init__(self):
        self.__chunked = {}
        self.__data_list = []

    def __parse(self):
        byte_io = io.BytesIO()

        while 1:
            try:
                data = self.__data_list.pop(0)
                byte_io.write(data)
            except IndexError:
                break
            ''''''

        data = byte_io.getvalue()
        byte_io.close()
        rets = []

        while 1:
            pos = data.find(b"\r\n")

            if pos < 0:
                if data != b"":
                    self.__data_list.append(data)
                break

            end = pos + 2
            ssize = data[0:end]

            try:
                size = int(ssize, 16)
            except ValueError:
                break

            if size == 0:
                self.__is_finish = True
                break

            begin = end
            end = begin + size
            chunk = data[begin:end]

            if len(chunk) < size:
                self.__data_list.append(data)
                break

            begin = end + 2
            data = data[begin:]
            rets.append((size, chunk,))

        return rets

    def add_data(self, byte_data):
        if not byte_data:
            return

        if self.__is_finish:
            return

        self.__data_list.append(byte_data)

    def get_chunked_entity(self):
        """
        this function will return chunked_size+chunked_body
        :return:
        """
        chunks = self.__parse()
        rets = []

        for (size, chunk) in chunks:
            ssize = "%s\r\n" % hex(size)
            ssize = ssize.replace("0x", "")

            tmp_io = io.BytesIO()
            tmp_io.write(ssize.encode("utf-8"))
            tmp_io.write(chunk)
            tmp_io.write(b"\r\n")

            data = tmp_io.getvalue()
            tmp_io.close()

            rets.append(data)

        if self.__is_finish and not self.__is_ret_finish_flag:
            self.__data_list = []
            self.__is_ret_finish_flag = True
            rets.append(b"0\r\n\r\n")

        return rets

    def get_every_chunked_body(self):
        """得到每个块的真正内容,不包括长度
        :return:
        """
        chunks = self.__parse()
        rets = [chunk for (size, chunk) in chunks]

        return rets

    def is_finish(self):
        return self.__is_finish


class buidler(object):
    pass
