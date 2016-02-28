#!/usr/bin/env python3
"""UDP一定要设置超时，免得没有办法释放父类的资源
"""
import pywind.evtframework.handler.handler as handler
import pywind.lib.timer as timer


class udp_handler(handler.handler):
    # 需要发送的数据
    __sent = None
    __socket = None

    def __init__(self):
        super(udp_handler, self).__init__()
        self.__sent = {}
        self.__timer = timer.timer()

    def get_id(self, address):
        """根据地址生成唯一id"""
        return "%s-%s" % address

    def bind(self, address):
        self.socket.bind(address)

    def getsockname(self):
        return self.__socket.getsockname()

    def init_func(self, creator_fd, *args, **kwargs):
        pass

    def set_socket(self, s):
        s.setblocking(0)
        self.set_fileno(s.fileno())
        self.__socket = s

    def timeout(self):
        self.__sent = {}
        self.udp_timeout()

    def error(self):
        self.udp_error()

    def delete(self):
        self.udp_delete()

    def sendto(self, byte_data, address, flags=0):
        name = self.get_id(address)
        if name not in self.__sent:
            self.__sent[name] = []

        self.__sent[name].append((byte_data, flags, address,))
        return

    def evt_read(self):
        while 1:
            try:
                message, address = self.socket.recvfrom(16384)
            except BlockingIOError:
                break
            except:
                self.error()
                break
            self.udp_readable(message, address)
        return

    def evt_write(self):
        del_names = []

        for name in self.__sent:
            data_queue = self.__sent[name]
            break_loop = False

            while 1:
                try:
                    byte_data, flags, address = data_queue.pop(0)
                except IndexError:
                    break
                sent_size = self.socket.sendto(byte_data, flags, address)
                slice_data = byte_data[sent_size:]

                if slice_data:
                    break_loop = True
                    self.__sent[name].insert(0, (slice_data, flags, address,))
                    break
                continue

            if break_loop:
                break

            if not self.__sent[name]:
                del_names.append(name)
            ''''''

        for name in del_names:
            del self.__sent[name]

        if not self.__sent:
            self.udp_writable()

        return

    def udp_readable(self, message, address):
        """重写这个方法
        :return:
        """
        pass

    def udp_writable(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_timeout(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_delete(self):
        """重写这个方法
        :return:
        """
        pass

    def udp_error(self):
        """重写这个方法
        :return:
        """
        pass

    @property
    def socket(self):
        return self.__socket
