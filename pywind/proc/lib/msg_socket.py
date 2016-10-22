import socket
import pywind.lib.reader as reader


class ProtocolErr(Exception): pass


class msg_socket(socket.socket):
    """进程间通讯协议
    sync_code:8 bytes,每个字节固定为 0x00
    payload_length:2 bytes 内容长度
    payload_content
    """
    # 一个帧是否结束
    __frame_finish = True
    __reader = None
    __sync_code = None

    __payload_length = 0
    __read_length = 0

    __received_data = None

    def __init__(self, family):
        super(msg_socket, self).__init__(family, socket.SOCK_STREAM)
        self.__frame_finish = True
        self.__reader = reader.reader()
        self.__sync_code = bytes(8)
        self.__reset()

    def __wrap_sent_data(self, byte_data):
        size = len(byte_data)
        sent_data = b"".join([
            self.__sync_code,
            bytes(((size & 0xff00) >> 8, size & 0x00ff,)),
            byte_data,
        ])

        return sent_data

    def __parse_recv_data(self, byte_data):
        self.__reader._putvalue(byte_data)

        if self.__frame_finish:
            if self.__reader.size() < 10: return (False, b"",)
            sync_code = self.__reader.read(8)
            if sync_code != self.__sync_code: raise ProtocolErr("wrong sync code")
            tmp_data = self.__reader.read(2)
            self.__payload_length = (tmp_data[0] << 8) | tmp_data[1]

        if self.__payload_length < self.__reader.size():
            read_length = self.__payload_length
        else:
            read_length = self.__reader.size()

        read_data = self.__reader.read(read_length)
        self.__read_length += read_length
        read_ok = self.__payload_length == self.__read_length

        return (read_ok, read_data,)

    def recv(self, bufsize, *args, **kwargs):
        bufsize += 10
        recv_data = self.recv(bufsize, *args, **kwargs)

        read_ok, byte_data = self.__parse_recv_data()
        self.__received_data.append(byte_data)

        if not read_ok: self.recv(bufsize, *args, **kwargs)

        ret_data = b"".join(self.__received_data)
        self.__reset()

        return ret_data

    def send(self, byte_data, *args, **kwargs):
        sent_data = self.__wrap_sent_data(byte_data)

        return self.__socket.send(sent_data, *args, **kwargs)

    def __reset(self):
        self.__payload_length = 0
        self.__read_length = 0
        self.__frame_finish = True
        self.__received_data = []
