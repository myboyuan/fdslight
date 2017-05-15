#!/usr/bin/env python3
import hashlib
import os
import random
import time
import urllib.parse

import pywind.lib.reader as reader
import pywind.web.lib.multipart as http_multipart


class RequestErr(Exception): pass


class MethodNotAllowErr(Exception): pass


class ContentLengthTooLongErr(Exception): pass


class ResponseErr(Exception): pass


class _request(object):
    MAX_BODY_SIZE = 8 * 1024 * 1024

    __qs_params = None
    __stream_params = None

    __read_size = 0
    __content_length = 0
    __env = None
    __files = None

    __tmp_dir = "./"

    __FORM_TYPE_URLENCODED = 1
    __FORM_TYPE_MULTIPART = 2
    __FORM_TYPE_PLAIN = 3
    __FORM_TYPE_UNKOWN = 4

    # multipart上传的boundary
    __multipart_boundary = ""
    __allow_request_methods = None

    __form_type = 0
    __reader = None

    __tmpfile_fd = None
    __tmpfile_name = ""

    __args = None
    __kwargs = None

    __cookie = None

    __multipart = None

    def __init__(self, env, *args, **kwargs):
        self.__qs_params = {}
        self.__stream_params = {}
        self.__env = env
        self.__files = {}
        self.__allow_request_methods = ["GET", "POST", ]
        self.__reader = reader.reader()
        self.__args = args
        self.__kwargs = kwargs
        self.__cookie = None
        self.__multipart = None

    @property
    def args(self):
        return self.__args

    @property
    def kwargs(self):
        return self.__kwargs

    def init(self):
        m = self.environ["REQUEST_METHOD"].upper()
        if m not in self.__allow_request_methods: raise MethodNotAllowErr("not allow method %s" % m)
        self.__content_length = int(self.environ["CONTENT_LENGTH"])

        if self.__content_length > self.MAX_BODY_SIZE: raise ContentLengthTooLongErr

        if m != "POST":
            self.__init_other_m()
            return
        self.__init_post_m()

    def __init_post_m(self):
        """post方法的初始化"""
        form_type = self.__get_post_form_type()
        if form_type == self.__FORM_TYPE_UNKOWN: raise RequestErr("unkown form type")
        if form_type == self.__FORM_TYPE_PLAIN: pass
        if form_type == self.__FORM_TYPE_MULTIPART:
            boundary = self.__get_form_multipart_boundary()
            if not boundary: raise RequestErr("wrong multipart boundary")
            self.__multipart_boundary = boundary
            return
        if form_type == self.__FORM_TYPE_URLENCODED: pass

    def __init_other_m(self):
        """其它请求方法的初始化"""
        pass

    def __get_tmpfile_name(self):
        sts = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        m = len(sts) - 1
        tmpname = ""

        while 1:
            tmplist = []
            for i in range(16):
                n = random.randint(0, m)
                tmplist.append(sts[n])
            tmpname = "".join(tmplist)
            path = "%s/%s" % (self.__tmp_dir, tmpname,)
            if not os.path.isfile(path): break

        return tmpname

    @property
    def read_size(self):
        return self.__read_size

    @property
    def content_length(self):
        return self.__content_length

    @property
    def environ(self):
        return self.__env

    @property
    def cookie(self):
        if self.__cookie == None: return self.__cookie
        self.__cookie = {}

        sts = self.environ.get("HTTP_COOKIE", "")
        tmplist = sts.split(";")

        for s in tmplist:
            s = s.lstrip()
            p = s.find("=")
            if s < 1: continue
            name = s[0:p]
            p += 1
            value = s[p:]

            if name not in self.__cookie:
                self.__cookie[name] = value
            else:
                if not isinstance(self.__cookie[name], list):
                    self.__cookie[name] = [self.__cookie[name], value]
                else:
                    self.__cookie[name].append(value)
                ''''''
            ''''''
        return

    def recv_ok(self):
        """数据是否接收完毕"""
        return self.read_size == self.content_length

    def __handle_multipart_body(self):
        if not self.__multipart:
            self.__multipart = http_multipart.parser(self.__multipart_boundary)

        self.__multipart.input(self.__reader.read())
        while 1:
            self.__multipart.parse()
            if self.__multipart.is_start():
                data = self.__multipart.get_data()
                if not data: continue
        return

    def handle_body(self):
        if self.recv_ok(): return
        byte_data = self.environ["wsgi.input"].read()
        rsize = self.content_length - self.read_size
        w_data = byte_data[0:rsize]

        self.__reader._putvalue(w_data)
        self.__read_size += len(w_data)

        if self.environ["REQUEST_METHOD"].upper() == "POST" and self.__form_type == self.__FORM_TYPE_MULTIPART:
            self.__handle_multipart_body()
            return

    def __get_argument(self, arguments, name, default, is_seq=False):
        if name not in arguments: return default
        seq = arguments[name]
        if not seq: return default
        if is_seq: return seq

        return seq[0]

    def __get_post_form_type(self):
        match_set = (
            "application/x-static-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        )

        content_type = self.environ.get("CONTENT_TYPE", "")
        match_rs = self.__FORM_TYPE_UNKOWN

        for s in match_set:
            p = content_type.lower().find(s)
            if p != 0: continue
            if p == match_set[0]: match_rs = self.__FORM_TYPE_URLENCODED
            if p == match_set[1]: match_rs = self.__FORM_TYPE_MULTIPART
            if p == match_set[2]: match_rs = self.__FORM_TYPE_PLAIN

        return match_rs

    def __get_form_multipart_boundary(self):
        content_type = self.environ["CONTENT_TYPE"]
        sts = content_type[20:].lstrip()

        return sts[9:]

    def get_argument(self, name, default=None, is_qs=True, is_seq=False):
        if is_qs:
            if not self.__qs_params: self.__qs_params = urllib.parse.parse_qs(self.__env["QUERY_STRING"])
            return self.__get_argument(self.__qs_params, name, default, is_seq)

        if None == self.__stream_params: return default
        return self.__get_argument(self.__stream_params, name, default, is_seq)

    @property
    def files(self):
        return self.__files

    def set_tmp_dir(self, directory):
        """设置临时目录"""
        self.__tmp_dir = directory

    def release(self):
        """释放占用的资源"""
        # 清理http body临时文件
        if self.__tmpfile_fd: self.__tmpfile_fd.close()
        path = "%s/%s" % (self.__tmp_dir, self.__tmpfile_name,)
        if os.path.isfile(path): os.remove(path)

        # 清理上传的文件
        tmpfiles = []
        for _, info in self.__files.items():
            for m in info: tmpfiles.append(m["tmp_name"])
        for tmp_name in tmpfiles:
            path = "%s/%s" % (self.__tmp_dir, tmp_name)
            if os.path.isfile(path): os.remove(path)

        self.__reader.flush()

    def set_allow_methods(self, method_list):
        """设置允许的请求方法"""
        self.__allow_request_methods = []
        for m in method_list: self.__allow_request_methods.append(m.upper())

    def get_raw_body(self):
        """获取未加工的http body文件对象
        :return object,对于POST上传类型,始终返回值为None,
        """
        if self.environ["REQUEST_METHOD"] == "POST": return None
        return self.__reader


class handler(object):
    __wait_sent = None
    __request = None

    __is_start_response = False

    chunked_response = False

    __start_response = None
    __is_response_header = False

    __resp_headers = None
    __resp_status = None
    __continue = True
    __is_finish = False

    # 块相应是否结束
    __chunked_finish = False

    def __init__(self, environ, start_response, *args, **kwargs):
        self.__wait_sent = []
        self.__start_response = start_response
        self.__resp_headers = []
        self.__resp_status = "200 OK"
        self.__request = _request(environ, *args, **kwargs)

        self.__continue = self.initialize()

        try:
            self.__request.init()
        except MethodNotAllowErr:
            self.set_status("405 Method Not Allowed")
            self.finish()
        except ContentLengthTooLongErr:
            self.set_status("413 Request Entity Too Large")
            self.set_header("Content-Length", 0)
            self.finish()
        except RequestErr:
            self.set_status("400 Bad Request")
            self.set_header("Content-Length", 0)
            self.finish()

    def on_recv_stream(self):
        """根据需要重写这个方法,接受http body流"""
        self.request.handle_body()

    @property
    def request(self):
        return self.__request

    def close(self):
        self.request.release()
        self.release()

    def release(self):
        """用于释放资源,重写这个方法"""
        pass

    def set_cookie(self, name, value, expires=-1, path="/", security=False, httponly=False, **kwargs):
        tmplist = ["%s=%s; path=%s" % (name, value, path,)]
        tmplist.append("max-age=%s" % expires)

        t = time.gmtime(time.time() + expires)
        sts = time.strftime("expires=%a, %d %b %Y %H:%M:%S GMT", t)
        tmplist.append(sts)

        for tp in kwargs.items(): tmplist.append("%s=%s" % tp)

        if security: tmplist.append("secure")
        if httponly: tmplist.append("httponly")

        sts = "; ".join(tmplist)
        self.set_header("Set-Cookie", sts)

    def set_status(self, status):
        try:
            _ = int(status[0:3])
        except ValueError:
            raise ResponseErr("wrong http response code")
        self.__resp_status = status

    def set_header(self, name, value):
        self.__resp_headers.append((name, value,))

    def set_headers(self, seq):
        self.__resp_headers += seq

    def initialize(self):
        """重写这个方法
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def handle(self):
        """重写这个方法,以添加自己的处理逻辑"""
        self.set_status("403 Forbidden")
        self.finish()

    def redirect(self, uri, qs_seq=None, stcode=302):
        """
        :param uri:重定向URI 
        :param qs_seq: 地址栏的query string,格式为[(name1,value1),(name2,value2),..]
        :param stcode: 
        :return: 
        """
        if stcode not in (301, 302): raise ValueError("the stcode must be from 301,302")

        if stcode == 301:
            status = "301 Moved Permanently"
        else:
            status = "302 Move temporarily"

        if qs_seq:
            seq = []
            for k, v in qs_seq:
                seq.append("%s=%s" % (k, v,))
            location = "%s?%s" % (uri, "&".join(seq))
        else:
            location = uri

        self.set_status(status)
        self.set_header("Location", location)
        self.finish()

    def __handle(self):
        if not self.__is_start_response and not self.request.recv_ok():
            self.on_recv_stream()
            return
        if self.request.recv_ok(): self.handle()

    def __iter__(self):
        if not self.__continue: return self
        if not self.__is_finish: self.__handle()

        if self.__is_start_response and not self.__is_response_header:
            stcode = int(self.__resp_status[0:3])
            self.__start_response(self.__resp_status, self.__resp_headers)
            if stcode >= 200:
                self.__is_response_header = True

        return self

    def __next__(self):
        try:
            resp_data = self.__wait_sent.pop(0)
        except IndexError:
            raise StopIteration

        return resp_data

    def __write_chunked(self, byte_data):
        length = len(byte_data)
        sts = hex(length)[2:]
        w = "%s\r\n" % sts
        if length == 0:
            self.__chunked_finish = True
            self.__wait_sent.append(b"\r\n")
            return
        self.__wait_sent.append(w.encode())

    def write(self, byte_data):
        self.__is_start_response = True
        if self.chunked_response:
            self.__write_chunked(byte_data)
            return
        if byte_data == b"": return
        self.__wait_sent.append(byte_data)

    def finish(self, byte_data=b""):
        self.__is_start_response = True
        self.__is_finish = True
        if self.chunked_response:
            if not self.__chunked_finish: self.__write_chunked(b"")
            return
        content_length = len(byte_data)
        self.set_header("Content-Length", content_length)
        self.__wait_sent.append(byte_data)

    def finish_with_bytes(self, content_type, byte_data):
        self.set_status("200 OK")
        self.set_header("Content-Type", content_type)
        self.finish(byte_data)

    def get_header_date(self, seconds):
        """生成WEB常用的GMT时间格式"""
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(seconds))

    def get_time_from_header_date(self, s):
        """把web请求头中的date解析成本地的秒时间"""
        try:
            struct_time = time.strptime(s, "%a, %d %b %Y %H:%M:%S GMT")
        except ValueError:
            return None

        return time.mktime(time.localtime(time.mktime(struct_time)))

    def calc_file_md5(self, fpath):
        """计算文件md5"""
        obj = hashlib.md5()
        with open(fpath, "rb") as f:
            while 1:
                rdata = f.read(8192)
                if not rdata: break
                obj.update(rdata)
        return obj.digest()
