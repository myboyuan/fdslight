#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httpclient as httpclient_lib
import socket, ssl


class httpclient(tcp_handler.tcp_handler):
    __parser = None
    __builder = None

    __ssl_on = None
    __ssl_handshake_ok = None

    __host = None
    __timeout = 0

    __req_callback = None
    __resp_callback = None
    __err_callback = None

    def init_func(self, creator, address, req_callback,
                  resp_callback, err_callback, timeout=10, ssl_on=False, certs=None,
                  is_ipv6=False
                  ):
        if is_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        self.__ssl_on = ssl_on
        self.__ssl_handshake_ok = False
        self.__host = address[0]
        self.__timeout = timeout
        self.__resp_callback = resp_callback
        self.__req_callback = req_callback
        self.__err_callback = err_callback

        s = socket.socket(af, socket.SOCK_STREAM)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        ctx = ssl._create_unverified_context()
        ver_info = ssl.OPENSSL_VERSION_INFO

        # 只有Opessl 1,0,2及其以上才支持ALPN
        if ver_info[0] >= 1 and ver_info[1] >= 0 and ver_info[1] >= 2:
            is_alpn = True
        else:
            is_alpn = False

        if self.__ssl_on and is_alpn:
            # ctx.set_alpn_protocols(['h2', 'http/1.1'])
            ctx.set_alpn_protocols(['http/1.1'])

        if self.__ssl_on:
            s = ctx.wrap_socket(self.socket, server_hostname=self.__host)
            self.set_socket(s)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def evt_read(self):
        try:
            super(httpclient, self).evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)

    def evt_write(self):
        try:
            super(httpclient, self).evt_read()
        except ssl.SSLWantReadError:
            pass

    def tcp_readable(self):
        if self.__ssl_on and not self.__ssl_handshake_ok:
            pass

        if not self.__ssl_on and not self.__parser:
            self.__parser = httpclient_lib._parser()

        rdata = self.reader.read()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

        self.__err_callback()
        self.delete_handler(self.fileno)
