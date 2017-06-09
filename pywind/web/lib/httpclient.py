#!/usr/bin/env python3

import pywind.web.lib.httputils as httputils
import pywind.lib.reader as reader


class HttpErr(Exception): pass


class _httpclient(object):
    __reader = None

    def __init__(self):
        self.__reader = reader.reader()

    @property
    def reader(self):
        return self.__reader

    def build_request(self, host, path="/", qs_seq=None):
        """重写这个方法
        :param host:
        :param path:
        :param qs_seq:
        :return bytes:
        """

    def parse_response_data(self, byte_data):
        """解析响应数据,重写这个方法
        :param byte_data:
        :return:
        """
        pass

    def build_send_body(self, byte_data):
        """一次性发送body数据,重写这个方法
        :param byte_data:
        :return bytes:
        """
        pass

    def build_send_body_part(self, byte_data):
        """分批次发送body数据,注意需要手动设置content length
        :param byte_data:
        :return bytes:
        """
        pass

    def parse_response_body(self, byte_data):
        """重写这个方法
        :param byte_data:
        :return:
        """
        pass

    def response_header_ok(self):
        """响应头部是否完成,重写这个方法
        :return Boolean:
        """
        pass

    def response_body_ok(self):
        """响应数据是否完成,重写这个方法
        :return Boolean:
        """
        pass

    def set_header(self, name, value):
        """重写这个方法
        :param name:
        :param value:
        :return:
        """
        pass

    def set_headers(self, seq):
        for k, v in seq: self.set_header(k, v)


class http1xclient(_httpclient):
    __headers = None
    __resp_header_ok = None
    __resp_body_ok = None

    def __init__(self):
        super(http1xclient, self).__init__()
        self.__headers = []
        self.__resp_header_ok = False
        self.__resp_body_ok = False

    def build_request(self, method, host, path="/", qs_seq=None):
        self.__host = host
        method = method.upper()

        if not qs_seq:
            uri = path
        else:
            uri = "%s?%s" % (path, "&".join(qs_seq))

        self.__headers.append(("Host", host))
        sts = httputils.build_http1x_req_header(method, uri, self.__headers)

        return sts.encode("iso-8859-1")

    def build_send_body(self, byte_data):
        return byte_data

    def set_header(self, name, value):
        if name.lower() == "host": return

    def build_send_body_part(self, byte_data):
        return byte_data

    def __parse_header(self):
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

        self.__resp_header_ok = True
        self.reader._putvalue(body_data)

    def __parse_response_body(self):
        pass

    def parse_response_data(self, byte_data):
        self.reader._putvalue(byte_data)

        if not self.__resp_header_ok:
            self.__parse_header()

        if not self.__resp_header_ok: return
        self.__parse_response_body()
