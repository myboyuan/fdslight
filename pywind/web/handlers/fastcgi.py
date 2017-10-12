#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.wsgi as wsgi
import socket, os, time, struct

_FCGI_PUB_HDR_SIZE = 8
_FCGI_PUB_HDR_FMT = "!BBHHBx"

_FCGI_BEGIN_REQ_SIZE = 8
_FCGI_BEGIN_REQ_FMT = "!HB5x"

_FCGI_END_REQ_SIZE = 8
_FCGI_END_REQ_FMT = "!IB3x"


def _parse_pub_header(header_data):
    return struct.unpack(_FCGI_PUB_HDR_FMT, header_data)


def _build_pub_header(_type, requestId, contentLength, paddingLength, version=1):
    return struct.pack(_FCGI_PUB_HDR_FMT, version, _type, requestId, contentLength, paddingLength, 0)


def _parse_begin_req_body(byte_data):
    return struct.unpack(_FCGI_BEGIN_REQ_FMT, byte_data)


def _build_begin_req_body(role, flags):
    return struct.pack(_FCGI_BEGIN_REQ_FMT, role, flags)


def _parse_end_req_body(byte_data):
    return struct.unpack(_FCGI_END_REQ_FMT, byte_data)


def _build_end_req_body(app_status, protocol_status):
    return struct.pack(_FCGI_END_REQ_FMT, app_status, protocol_status)


class fcgid_listen(tcp_handler.tcp_handler):
    # 最大连接数
    __max_conns = 0
    __current_conns = 0
    __configs = None
    __wsgi = None

    def init_func(self, creator_fd, configs):
        self.__configs = configs
        self.__max_conns = configs.get("max_conns", 10)
        use_unix_socket = configs.get("use_unix_socket", False)
        if use_unix_socket:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            s = socket.socket()
        listen = configs.get("listen", ("127.0.0.1", 8000,))

        if use_unix_socket and os.path.exists(listen): os.remove(listen)

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
            if self.__current_conns == self.__max_conns:
                cs.close()
                continue
            self.create_handler(self.fileno, fcgi_handler, cs, caddr, self.__configs)
            self.__current_conns += 1

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "close_conn": return
        self.__current_conns -= 1

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class fcgi_handler(tcp_handler.tcp_handler):
    __creator = -1
    __application = None
    __timeout = 0
    __mtime = None

    def init_func(self, creator_fd, cs, caddr, configs):
        self.__creator = creator_fd
        self.__application = configs.get("application", None)
        self.__timeout = configs.get("timeout", 30)
        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.__mtime = time.time()

        return self.fileno

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        pass

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
