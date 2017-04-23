#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as websocket
import pywind.web.lib.httputils as httputils
import socket


class ws_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, listen, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
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

    __is_handshake = None

    # 自定义的握手响应头
    __ext_handshake_resp_headers = None

    def init_func(self, creator, cs, caddr):
        self.__caddr = caddr

        self.__decoder = websocket.decoder(server_side=True)
        self.__encoder = websocket.encoder(server_side=True)

        self.__is_handshake = False
        self.__ext_handshake_resp_headers = []

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    @property
    def caddr(self):
        return self.__caddr

    def response_error(self):
        resp_sts = httputils.build_http1x_resp_header(
            "400 Bad Request",
            [
                ("Sec-WebSocket-Version", 13),
            ],
            version="1.1"
        )

        self.writer.write(resp_sts.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

        self.delete_this_no_sent_data()

    def __do_handshake(self, byte_data):
        try:
            sts = byte_data.decode("iso-8859-1")
        except UnicodeDecodeError:
            self.response_error()
            return False

        try:
            rs = httputils.parse_htt1x_request_header(sts)
        except:
            self.response_error()
            return False

        req, headers = rs

        dic = {}
        for k, v in headers:
            k = k.lower()
            dic[k] = v

        if "sec-websocket-key" not in dic: return False
        ws_version = dic.get("sec-websocket-version", 0)

        is_err = False
        try:
            ws_version = int(ws_version)
            if ws_version != 13: is_err = True
        except ValueError:
            is_err = True
        if is_err:
            self.response_error()
            return False

        if not self.on_handshake(req, headers):
            self.response_error()
            return False

        sec_ws_key = dic["sec-websocket-key"]
        resp_sec_key = websocket.gen_handshake_key(sec_ws_key)

        resp_headers = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", resp_sec_key)
        ]

        resp_headers += self.__ext_handshake_resp_headers

        resp_sts = httputils.build_http1x_resp_header(
            "101 Switching Protocols",
            resp_headers,
            version="1.1"
        )

        self.writer.write(resp_sts.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

        return True

    def on_handshake(self, request, headers):
        """重写这个方法
        :param request: 
        :param headers: 
        :return Boolean: False表示握手不允许,True表示握手允许 
        """
        return True

    def set_handshake_resp_header(self, name, value):
        """设置额外的响应头
        :param name: 
        :param value: 
        :return: 
        """
        self.__ext_handshake_resp_headers.append((name, value,))

    def set_ws_timeout(self, timeout):
        self.__conn_timeout = timeout

    def tcp_readable(self):
        rdata = self.reader.read()

        if not self.__is_handshake:
            if not self.__do_handshake(rdata): return
            self.__is_handshake = True
            return

        self.__decoder.input(rdata)
        self.ws_readable()

    @property
    def decoder(self):
        return self.__decoder

    @property
    def encoder(self):
        return self.__encoder

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.ws_close()
        self.unregister(self.fileno)
        self.close()

    def tcp_timeout(self):
        pass

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
        while self.decoder.continue_parse():
            self.decoder.parse()

            if self.decoder.frame_ok():
                data = self.decoder.get_data()
                self.decoder.reset()
                print(data)

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
