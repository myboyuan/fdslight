#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httpclient as httpclient_lib
import socket, ssl


class httpclient(tcp_handler.tcp_handler):
    __parser = None
    __builder = None

    __ssl_on = None

    __host = None
    __timeout = 0

    __req_callback = None
    __resp_callback = None
    __err_callback = None

    # 是否是HTTP1x协议
    __is_http1x = None
    __request_ok = None

    # 是否选择了协议
    __is_selected_protocol = None

    # 是否支持ALPN
    __is_support_alpn = None

    def init_func(self, creator, address, req_callback,
                  resp_callback, err_callback, timeout=10, ssl_on=False, certs=None,
                  is_ipv6=False
                  ):
        if is_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        self.__ssl_on = ssl_on
        self.__host = address[0]
        self.__timeout = timeout
        self.__resp_callback = resp_callback
        self.__req_callback = req_callback
        self.__err_callback = err_callback
        self.__is_http1x = True
        self.__request_ok = False
        self.__is_selected_protocol = False
        self.__is_support_alpn = False

        s = socket.socket(af, socket.SOCK_STREAM)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        if self.__ssl_on:
            ctx = ssl._create_unverified_context()
            ver_info = ssl.OPENSSL_VERSION_INFO

        is_alpn = False
        # 只有Opessl 1,0,2及其以上才支持ALPN
        if self.__ssl_on:
            if ver_info[0] >= 1 and ver_info[1] >= 0 and ver_info[1] >= 2:
                is_alpn = True
            else:
                is_alpn = False
            ''''''
        if self.__ssl_on and is_alpn:
            # ctx.set_alpn_protocols(['h2', 'http/1.1'])
            ctx.set_alpn_protocols(['http/1.1'])

        self.__is_support_alpn = is_alpn

        if self.__ssl_on:
            s = ctx.wrap_socket(self.socket, server_hostname=self.__host)
            self.set_socket(s)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.add_evt_write(self.fileno)

    def evt_read(self):
        try:
            super(httpclient, self).evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)

    def evt_write(self):
        try:
            super(httpclient, self).evt_write()
        except ssl.SSLWantReadError:
            pass

    def tcp_readable(self):
        if self.__ssl_on and not self.__is_selected_protocol:
            if not self.__is_support_alpn:
                self.__is_http1x = True
            else:
                protocol = self.socket.selected_alpn_protocol()
                if protocol == "http/1.1":
                    self.__is_http1x = True
                else:
                    self.__is_http1x = False
            self.__is_selected_protocol = True

        if self.__is_http1x:
            self.__parser = httpclient_lib.http1x_parser()
        else:
            self.__parser = httpclient_lib.http2x_parser()

        self.set_timeout(self.fileno, self.__timeout)
        rdata = self.reader.read()

        self.__parser.parse(rdata)
        self.__resp_callback(self.__parser)

    def tcp_writable(self):
        if not self.__is_selected_protocol and self.__ssl_on: return
        self.remove_evt_write(self.fileno)
        if self.__request_ok: return

        if not self.__builder:
            if self.__is_http1x:
                self.__builder = httpclient_lib.http1x_builder()
            else:
                self.__builder = httpclient_lib.http2x_builder()
        self.__request_ok = self.__req_callback(self.__builder)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.__err_callback()
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        self.__err_callback()
        self.delete_handler(self.fileno)

    def send_data(self, byte_data):
        self.set_timeout(self.fileno, self.__timeout)
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
