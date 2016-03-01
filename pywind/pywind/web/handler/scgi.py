#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import pywind.web.hooks._wsgi as wsgi
import socket
import pywind.lib.reader as reader


class _scgi_proto_error(Exception):
    pass


def _build_scgi_resp_header(status, headers):
    seq = ["Status: %s" % status]
    for t in headers:
        sts = "%s: %s" % t
        seq.append(sts)
    seq.append("\r\n")

    return "\r\n".join(seq)


class _scgi_parser(object):
    __reader = None
    __header_ok = False
    __body_ok = False
    __cgi_env = None

    __header_size = 0
    __total_size = 0
    __read_size = 0

    # 是否已经丢弃了逗号
    __is_drop_comma = False

    def __init__(self):
        self.__reader = reader.reader()
        self.__header = None

    def __parse_cgi_env(self):
        rdata = self.__reader.read(self.__header_size)
        sts = rdata.decode()
        tmp_seq = sts.split("\0")
        size = len(tmp_seq)
        if size % 2 != 1: raise _scgi_proto_error
        n = size - 1
        tmp_seq.pop(n)

        k_n = 0
        v_n = 1
        environ = {}

        while v_n <= n:
            name = tmp_seq[k_n]
            value = tmp_seq[v_n]
            k_n += 2
            v_n += 2
            environ[name] = value

        self.__cgi_env = environ
        self.__read_size += self.__header_size

    def __parse_header(self):
        if self.__header_size and self.__reader.size() < self.__header_size:
            return

        rdata = self.__reader.read()

        if rdata[0:14] != b"CONTENT_LENGTH":
            raise _scgi_proto_error
        if rdata[14] != 0:
            raise _scgi_proto_error
        tmp_seq = []
        n = 15
        cnt = 1
        while 1:
            try:
                if rdata[n] != 0:
                    tmp_seq.append(rdata[n])
                    n += 1
                    cnt += 1
                    continue
                ''''''
            except IndexError:
                self.__reader._putvalue(rdata)
                return None
            if cnt > 16: raise _scgi_proto_error
            if n == 15:
                tmp_seq.append(0)
                n += 1
                continue
            break
        try:
            content_len = int(bytes(tmp_seq).decode())
        except ValueError:
            raise _scgi_proto_error

        self.__header_size = self.__total_size - content_len
        self.__reader._putvalue(rdata)
        self.__header_ok = True
        self.__parse_cgi_env()

    def get_cgi_env(self):
        return self.__cgi_env

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        if self.__header_ok:
            return True

        if self.__reader.size() < 20:
            return False

        rdata = self.__reader.read(16)
        pos = rdata.find(b":")
        if pos < 0:
            raise _scgi_proto_error
        sts = rdata[0:pos].decode()
        try:
            total_len = int(sts)
        except ValueError:
            raise _scgi_proto_error

        self.__total_size = total_len
        n = pos + 1
        self.__reader.push(rdata[n:])
        self.__parse_header()

    def header_ok(self):
        return self.__header_ok

    def get_body(self):
        if not self.__is_drop_comma:
            if self.__reader.size() == 0:
                return b""
            self.__reader.read(1)
            self.__is_drop_comma = True
        n = self.__total_size - self.__read_size
        size = self.__reader.size()
        rdata = self.__reader.read(n)
        if size < n:
            self.__read_size += size
        else:
            self.__body_ok = True
            self.__read_size += n

        self.__reader.read()
        return rdata

    def body_ok(self):
        return self.__body_ok


class scgi_server(tcp_handler.tcp_handler):
    __client_address = None
    __config = None
    # 连接超时
    __conn_timeout = 60
    __scgi_parser = None
    # 是否删除写事件
    __del_write_ev = True

    def init_func(self, creator_fd, config, c_sock=None, c_addr=None):
        self.__config = config
        if c_sock:
            self.set_socket(c_sock)
            self.__client_address = c_addr
            self.__scgi_parser = _scgi_parser()

            self.register(self.fileno)
            self.add_evt_read(self.fileno)

            return self.fileno

        address = self.__config["listen"]
        s = socket.socket()
        self.set_socket(s)
        self.bind(address)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, scgi_server, self.__config, cs, address)
        return

    def tcp_readable(self):
        self.set_timeout(self.fileno, self.__conn_timeout)
        rdata = self.reader.read()
        # 丢弃多余的数据包
        if self.__scgi_parser.body_ok(): return
        self.__scgi_parser.input(rdata)
        self.__scgi_parser.parse()

        if not self.__scgi_parser.header_ok(): return
        if self.__scgi_parser.header_ok() and not self.hook_exists("wsgi"):
            self.hook_register("wsgi",
                               wsgi.wsgi_hook,
                               "wsgi", self.__config, self.__scgi_parser.get_cgi_env()
                               )

        self.hook_input("wsgi", self.__scgi_parser.get_body())

    def tcp_writable(self):
        if not self.__del_write_ev:
            self.get_hook("wsgi").wake_up_for_writable()
            return

        if self.writer.size() < 1: self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.delete_hook("wsgi")
        self.unregister(self.fileno)
        self.close()

    def tcp_timeout(self):
        self.delete_handler(self.fileno)

    def hook_output(self, name, byte_data):
        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)
        self.set_timeout(self.fileno, self.__conn_timeout)

    def __resp_finish(self):
        self.delete_this_no_sent_data()

    def __resp_header(self, status, headers):
        header = _build_scgi_resp_header(status, headers)

        self.writer.write(header.encode())
        self.add_evt_write(self.fileno)

    def handler_ctl_from_hook(self, from_hook, cmd, *args):
        if cmd not in ("resp_header", "resp_finish", "freq_mode", "sleep_mode"):
            return False

        if cmd == "resp_header":
            resp_status, resp_headers = args
            self.__resp_header(resp_status, resp_headers)
            return True

        if cmd == "resp_finish":
            self.__resp_finish()
            return True

        if cmd == "freq_mode":
            self.__del_write_ev = False
            self.add_evt_write(self.fileno)
            return True

        if cmd == "sleep_mode":
            self.__del_write_ev = True
            return True

        return False
