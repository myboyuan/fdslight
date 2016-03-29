#!/usr/bin/env python3
import queue, io


class writer(object):
    __buff_queue = None
    __size = 0
    __lifo = None

    def __init__(self):
        self.__buff_queue = queue.Queue()
        self.__lifo = queue.LifoQueue()
        self.__closed = False
        self.__size = 0

    def is_empty(self):
        if self.__size < 1:
            return True

        return False

    def write(self, bdata):
        slice_size = 8192
        bsize = len(bdata)
        end = 0
        begin = 0

        while 1:
            if end >= bsize: break
            if begin + slice_size > bsize:
                end = bsize
            else:
                end = begin + slice_size
            data = bdata[begin:end]
            begin = end

            self.__buff_queue.put(data)
            self.__size += len(data)

        return

    def writeline(self, bdata=b""):
        byteio = io.BytesIO()
        writes = [bdata, "\r\n".encode("utf-8")]

        for v in writes:
            byteio.write(v)

        bdata = byteio.getvalue()
        byteio.close()

        self.write(bdata)

    def writelines(self, byte_list):
        byteio = io.BytesIO()

        for v in byte_list:
            byteio.write(v)
            byteio.write("\r\n".encode("utf-8"))

        bdata = byteio.getvalue()
        byteio.close()

        self.write(bdata)

    def push(self, byte_data):
        # cut down empty list data
        # decreasing Memory Consumption
        if byte_data == b"":
            return

        self.__size += len(byte_data)
        self.__lifo.put(byte_data)

    def _getvalue(self):
        byte_io = io.BytesIO()

        while 1:
            try:
                v = self.__lifo.get_nowait()
            except queue.Empty:
                try:
                    v = self.__buff_queue.get_nowait()
                except queue.Empty:
                    break
                ''''''

            byte_io.write(v)
            self.__size -= len(v)

        ret = byte_io.getvalue()
        byte_io.close()

        return ret

    def flush(self):
        _ = self._getvalue()

    def size(self):
        return self.__size
