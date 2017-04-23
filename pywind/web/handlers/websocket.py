#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as websocket
import socket


class ws_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, listen, conn_timeout=600, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(listen)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break

            self.create_handler(
                self.fileno, ws_handler, cs, caddr
            )
        ''''''

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class ws_handler(tcp_handler.tcp_handler):
    __conn_timeout = 60
    __caddr = None

    __encoder = None
    __decoder = None

    def init_func(self, creator, cs, caddr, conn_timeout):
        self.__conn_timeout = conn_timeout
        self.__caddr = caddr

        self.__decoder = websocket.decoder()
        self.__encoder = websocket.encoder()

        self.set_socket(cs)

        return self.fileno

    @property
    def caddr(self):
        return self.__caddr

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def getmsg(self):
        """获取websocket消息
        :return: 
        """
        pass

    def sendmsg(self, msg, *args, **kwargs):
        """发送websocket消息
        :param msg: 
        :param args: 
        :param kwargs: 
        :return: 
        """
        pass

    def ws_readable(self):
        """重写这个方法
        :return: 
        """
        pass

    def ws_writable(self):
        """重写这个方法
        :return bytes:
        """
        pass

    def ws_close(self):
        """socket关闭的时候将会调用此方法,重写这个方法
        :return: 
        """
        pass
