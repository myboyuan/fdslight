import socket
import pywind.lib.reader as reader


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

    def __init__(self, family):
        super(msg_socket, self).__init__(family, socket.SOCK_STREAM)
        self.__frame_finish = True
        self.__reader = reader.reader()
        self.__sync_code = bytes(8)

    def __wrap_sent_data(self, byte_data):
        size = len(byte_data)
        sent_data = b"".join([
            self.__sync_code,
            bytes(((size & 0xff00) >> 8, size & 0x00ff,)),
            byte_data,
        ])

        return sent_data

    def recv(self, bufsize, *args, **kwargs):
        bufsize += 10
        recv_data = self.recv(bufsize, *args, **kwargs)

        if self.__frame_finish: pass

    def send(self, byte_data, *args, **kwargs):
        sent_data = self.__wrap_sent_data(byte_data)

        return self.__socket.send(sent_data, *args, **kwargs)

    