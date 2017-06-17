#!/usr/bin/env python3

import pywind.web.lib.httputils as httputils
import pywind.web.lib.httpchunked as httpchunked
import pywind.lib.reader as reader


class HttpErr(Exception): pass


class _builder(object):
    __req_headers = None

    def __init__(self):
        self.__req_headers = []

    def wrap_header(self, method, host, path, qs_seq, headers):
        """生成请求头
        :param method:
        :param path:
        :param qs_seq:
        :param headers
        :return bytes:
        """
        pass

    def wrap_body(self, byte_data):
        """装饰HTTP BODY
        :param byte_data:
        :return bytes:
        """
        pass

    def set_header(self, name, value):
        if name.lower() == "host": return
        self.__req_headers.append((name, value,))

    def set_headers(self, seq):
        for k, v in seq: self.set_header(k, v)

    def get_header_data(self, method, host, path="/", qs_seq=None):
        return self.wrap_header(method, host, path, qs_seq, self.__req_headers)

    def get_body_data(self, body_data):
        return self.wrap_body(body_data)

    def reset(self):
        self.__req_headers = []


class _parser(object):
    __reader = None

    __is_chunked = None

    header_ok = None

    __content_length = None
    __responsed_length = None

    __status = None
    __headers = None
    __chunked = None

    __is_start = False

    __data = None
    __cookies = None

    def __init__(self):
        self.__reader = reader.reader()
        self.header_ok = False
        self.__is_chunked = False
        self.__content_length = 0
        self.__responsed_length = 0
        self.__is_start = False
        self.__data = []
        self.__cookies = []

    def __parse_content_length(self):
        is_length = False
        is_chunked = False

        for k, v in self.__headers:
            name = k.lower()
            if name == "content-length":
                is_length = True
                try:
                    self.__content_length = int(v)
                except ValueError:
                    raise HttpErr("wrong content length value")
                continue

            if name == "transfer-encoding" and v.lower() == "chunked": is_chunked = True

        if is_length and is_chunked:
            raise HttpErr("conflict content length define")

        if is_chunked:
            self.__is_chunked = True
            self.__chunked = httpchunked.parser()
        return

    def __parse_header(self):
        self.unwrap_header()
        if not self.header_ok: return
        self.__is_start = True
        self.__parse_content_length()

    def __parse_body(self):
        rdata = self.reader.read()
        body_data = self.unwrap_body(rdata)

        if self.__is_chunked:
            self.__chunked.input(body_data)

            try:
                self.__chunked.parse()
            except httpchunked.ChunkedErr:
                raise HttpErr("wrong chunked body")

            data = self.__chunked.get_chunk()
            if not data: return
            self.__data.append(data)

            return

        size = len(body_data)
        n = self.__content_length - self.__responsed_length

        if size <= n:
            self.__responsed_length += size
        else:
            # 截断多余的数据
            self.__responsed_length = self.__content_length
            body_data = body_data[0:n]

        self.__data.append(body_data)

    def __parse_cookie(self, sts):
        """解析单个cookie
        :param sts:
        :return:
        """
        sts = sts.lstrip()
        if sts[0:4] != "name": return None
        tmplist = sts.split(";")
        tmplist2 = []

        for s in tmplist:
            if s: tmplist2.append(s.strip())
        s = tmplist2.pop()
        ret = {}

        sec = False
        if s.lower() == "secure":
            sec = True
        else:
            tmplist2.append(s)
        if sec and not self.__ssl_on: return None

        for s in tmplist2:
            p = s.find("=")
            if p < 1: continue
            name = s[0:p].strip()
            p += 1
            val = s[p:].strip()
            ret[name] = val

        return ret

    def response_ok(self):
        if self.__is_chunked:
            return self.__chunked.is_ok()

        return self.__responsed_length == self.__content_length and self.__is_start

    def unwrap_header(self):
        """重写这个方法
        :return:
        """
        pass

    def unwrap_body(self, body_data):
        """重写这个方法
        :param body_data
        :return:
        """
        pass

    def parse(self, byte_data):
        if self.response_ok(): return
        self.__reader._putvalue(byte_data)

        if not self.header_ok:
            self.__parse_header()

        if not self.header_ok: return
        self.__parse_body()

    @property
    def reader(self):
        return self.__reader

    def set_status(self, stcode):
        self.__status = stcode

    def set_headers(self, headers):
        seq = []

        # 为保证http1x和http2x协议的一致性
        # 字段名全部转换成小写
        for k, v in headers:
            seq.append((k.lower(), v))
        self.__headers = seq

        for k, v in self.__headers:
            if k != "set-cookie": continue
            cookie = self.__parse_cookie(v)
            if not cookie: continue
            self.__cookies.append(cookie)

    @property
    def status(self):
        return self.__status

    @property
    def headers(self):
        return self.__headers

    def reset(self):
        self.header_ok = False
        self.__is_chunked = False
        self.__content_length = 0
        self.__responsed_length = 0
        self.__is_start = False
        self.__cookies = []

    def get_data(self):
        data = b"".join(self.__data)
        self.__data = []

        return data

    @property
    def cookies(self):
        return self.__cookies

    @property
    def status(self):
        return self.__status


class http1x_builder(_builder):
    def wrap_header(self, method, host, path, qs_seq, headers):
        method = method.upper()

        if not qs_seq:
            uri = path
        else:
            uri = "%s?%s" % (path, "&".join(qs_seq))

        headers.append(("Host", host))
        sts = httputils.build_http1x_req_header(method, uri, headers)

        return sts.encode("iso-8859-1")

    def wrap_body(self, byte_data):
        return byte_data


class http1x_parser(_parser):
    def unwrap_header(self):
        size = self.reader.size()
        rdata = self.reader.read()

        p = rdata.find(b"\r\n\r\n")

        if p > 0 and p < 10: raise HttpErr("wrong http1x response header")
        if p < 0 and size > 8192: raise HttpErr("the http1x response header too long")

        if p < 0: return
        p += 4
        header_data = rdata[0:p]
        body_data = rdata[p:]

        sts = header_data.decode("iso-8859-1")

        try:
            resp, fields = httputils.parse_http1x_response_header(sts)
        except httputils.Http1xHeaderErr:
            raise HttpErr("wrong http response header")

        _, status = resp

        self.set_status(int(status[0:3]))
        self.set_headers(fields)

        self.reader._putvalue(body_data)
        self.header_ok = True

    def unwrap_body(self, body_data):
        return body_data


class http2x_parser(_parser):
    pass


class http2x_builder(_builder):
    pass


class client(object):
    __method = None
    __host = None
    __path = None
    __qs_seq = None

    __req_callback = None
    __resp_callback = None
    __err_callback = None

    __evtfw = None

    __fileno = None
    # 是否已经发送过头部数据
    __is_sent_header = False

    __sent_body_ok = None

    timeout = 10
    headers = None

    __ssl_on = None

    __parser = None
    __builder = None

    def __init__(self, req_callback, resp_callback, err_callback):
        from pywind.global_vars import global_vars

        self.__evtfw = global_vars["pyw.ioevtfw.dispatcher"]
        self.__fileno = None

        self.__req_callback = req_callback
        self.__resp_callback = resp_callback
        self.__err_callback = err_callback

        self.__sent_ok = False
        self.headers = []

    def request(self, method, host, path="/", qs_seq=None, ssl_on=False, port=None, is_ipv6=False):
        import pywind.web.handlers.httpclient as httpclient_handler

        if ssl_on and not port:
            port = 443
        if not ssl_on and not port:
            port = 80

        self.__method = method
        self.__host = host
        self.__path = path
        self.__qs_seq = qs_seq
        self.__ssl_on = ssl_on

        if not self.__fileno:
            self.__fileno = self.__evtfw.create_handler(
                -1, httpclient_handler.httpclient,
                (host, port,),
                self.__request_callback,
                self.__response_callback,
                self.__error_callback,
                timeout=self.timeout,
                ssl_on=ssl_on,
                is_ipv6=is_ipv6
            )
        self.__is_sent_header = False
        self.__sent_body_ok = False

    def __request_callback(self, http_builder):
        if not self.__is_sent_header:
            http_builder.set_headers(self.headers)
            header_data = http_builder.get_header_data(
                self.__method, self.__host,
                path=self.__path,
                qs_seq=self.__qs_seq
            )
            self.send_data(header_data)
            self.__is_sent_header = True

        self.__builder = http_builder
        self.__sent_body_ok = self.__req_callback()
        return self.__sent_body_ok

    def __response_callback(self, http_parser):
        self.__parser = http_parser
        self.__resp_callback(http_parser.get_data())

    def __error_callback(self):
        self.__err_callback()

    @property
    def cookies(self):
        return self.__parser.cookies

    @property
    def status(self):
        return self.__parser.status

    def send_data(self, byte_data):
        self.__evtfw.get_handler(self.__fileno).send_data(byte_data)

    def reset(self):
        if self.__parser:
            self.__parser.reset()
        if self.__builder:
            self.__builder.reset()
        return


"""
import socket

s = socket.socket()
s.connect(("www.baidu.com", 80))

parser = http1x_parser()
builder = http1x_builder()

builder.set_header("User-Agent", "Firefox")

header = builder.get_header_data("GET", "www.baidu.com")

s.send(header)
data = s.recv(4096)
parser.parse(data)

print(parser.headers)
print(parser.get_data())

s.close()
"""
