#!/usr/bin/env python3

import socket, ssl
import pywind.web.lib.httputils as httputils


class _httpclient(object):
    __headers = None
    __socket = None

    __io_wait = None

    __connect_ok = None

    def __init__(self):
        self.__headers = []
        self.__socket = None
        self.__io_wait = True
        self.__connect_ok = False

    def set_request_header(self, name, value):
        self.__headers.append((name, value,))

    def set_request_headers(self, seq):
        self.__headers += seq

    def set_socket(self, host, ssl_on=False, ipv6_on=False, io_wait=True):
        if ipv6_on:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        self.__io_wait = io_wait

        self.__socket = socket.socket(af, socket.SOCK_STREAM)
        if ssl_on:
            self.__socket = ssl.wrap_socket(self.__socket)

        if io_wait:
            self.__socket.connect(host)

    def get_headers(self):
        return self.__headers

    def request(self, method, host, path="/", qs_seq=None):
        """重写这个方法
        :param method:
        :param url:
        :param qs_seq:
        :return:
        """
        pass

    def request_header_ok(self):
        """头部请求是否已经发送完毕,重写这个方法
        :return:
        """
        pass

    def request_body_ok(self):
        """body部分是否已经发送完毕,重写这个方法
        :return:
        """
        pass

    def response_header_ok(self):
        """头部响应是否已经接收完毕,重写这个方法
        :return:
        """
        pass

    def response_body_ok(self):
        """body响应是否已经接收完毕,重写这个方法
        :return:
        """
        pass

    def get_body_data(self):
        """获取body数据,重写这个方法
        :return:
        """
        pass

    def parse_cookie(self, sts):
        """解析COOKIE
        :param sts:
        :return:
        """
        pass

    def connect_ok(self):
        """检测连接是否成功
        :return:
        """
        pass

    def write_data(self, byte_data):
        """写入数据
        :param byte_data:
        :return:
        """
        pass

    def read_data(self, byte_data):
        """读取数据
        :param byte_data:
        :return:
        """
        pass

    def loop(self):
        """循环函数
        :return:
        """
        pass


class _http1x_client(_httpclient):
    def request(self, method, host, path="/", qs_seq=None):
        m = method.upper()
        if not qs_seq:
            uri = path
        else:
            uri = "%s?%s" % (path, "&".join(qs_seq))

        header = httputils.build_http1x_req_header(
            m, uri, self.get_headers()
        )

        self.write_data(header.encode("iso-8859-1"))
        return


class _http2x_client(_httpclient):
    def request(self, method, host, path="/", qs_seq=None):
        pass


class httpclient(object):
    __http_instance = None

    __request_body_callback = None
    __response_body_callback = None

    def __init__(self):
        self.__http_instance = _http1x_client()

    def set_request_body_callback(self, func):
        """设置请求body部分回调函数
        :param func
        :return:
        """
        self.__request_body_callback = func

    def set_response_body_callback(self, func):
        """设置响应body部分回调函数
        :param func:
        :return:
        """
        self.__response_body_callback = func

    def request(self, method, host, path="/", qs_seq=None, ssl_on=False, auto_http2=False, ipv6_on=False):
        """请求页面
        :param method 请求方法
        :param host 请求主机
        :param path 请求路径
        :param qs_seq 执行字符串
        :param ssl_on: 是否打开SSL加密传输
        :param auto_http2: 是否自动升级到HTTP2,注意该选项只有开启SSL ON才生效,并且需要支持ALPN,否则会报错
        :param ipv6_on:是否开启IPV6请求
        """
        self.__http_instance.request(method, host, path=path, qs_seq=qs_seq)

    def set_request_header(self, name, value):
        self.__http_instance.set_request_header(name, value)

    def set_request_headers(self, seq):
        self.__http_instance.set_request_headers(seq)

    def waiting(self):
        """等待处理
        :return:
        """
        self.__http_instance.loop()

    def response_ok(self):
        """是否已经响应完毕
        :return:
        """
        pass
