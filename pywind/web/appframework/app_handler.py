#!/usr/bin/env python3
import urllib.parse, time, os, random, shutil
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

    def __init__(self, env, *args, **kwargs):
        self.__qs_params = {}
        self.__stream_params = {}
        self.__env = env
        self.__files = {}
        self.__allow_request_methods = ["GET", "POST", ]
        self.__reader = reader.reader()
        self.__args = args
        self.__kwargs = kwargs

        self.__init()

    @property
    def args(self):
        return self.__args

    @property
    def kwargs(self):
        return self.__kwargs

    def __init(self):
        m = self.environ["REQUEST_METHOD"].lower()
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

    def recv_ok(self):
        """数据是否接收完毕"""
        return self.read_size == self.content_length

    def __handle_multipart_body(self):
        if not self.recv_ok():
            if not self.__tmpfile_fd:
                tmpname = self.__get_tmpfile_name()
                self.__tmpfile_name = tmpname
                path = "%s/%s" % (self.__tmp_dir, tmpname,)
                self.__tmpfile_fd = open(path, "wb")
            self.__tmpfile_fd.write(self.__reader.read())
            return
        multipart = http_multipart.parser(self.__tmpfile_fd, self.__multipart_boundary)
        is_get_hdr = False
        info = None
        tmpfile_fd = None
        is_file = False
        data_list = []

        while not multipart.all_ok():
            if not multipart.single_ok() and not is_get_hdr:
                is_get_hdr = True
                info = multipart.get_info()
                is_file = info["is_file"]
                if is_file:
                    tmpname = self.__get_tmpfile_name()
                    path = "%s/%s" % (self.__tmp_dir, tmpname,)
                    tmpfile_fd = open(path, "wb")
                ''''''
            if is_get_hdr and not multipart.single_ok():
                try:
                    multipart.parse()
                except http_multipart.MultipartErr:
                    # 关闭占用的文件资源
                    if tmpfile_fd: tmpfile_fd.close()
                    raise RequestErr("wrong multipart format")
                # 去除结尾的\r\n
                if multipart.single_ok():
                    is_get_hdr = False
                    part_data = multipart.get_part_data()[0:-2]
                else:
                    part_data = multipart.get_part_data()
                tmpfile_fd.write(part_data)
                name = info["name"]
                if multipart.single_ok():
                    multipart.reset()
                    if not is_file:
                        try:
                            sts = b"".join(data_list).decode()
                        except UnicodeDecodeError:
                            raise RequestErr("wrong UTF coding")
                        if name not in self.__stream_params: self.__stream_params[name] = []
                        self.__stream_params[name].append(sts)
                        data_list = []
                    else:
                        tmpfile_fd.close()
                        tmpfile_fd = None
                        if name not in self.__files: self.__files[name] = []
                        self.__files[name].append({
                            "tmp_name": info["tmp_name"],
                            "filename": info["filename"],
                            "content_type": info["content_type"],
                        })
                    is_file = False
                """"""
            """"""
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
            "application/x-www-form-urlencoded",
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
    args = None
    kwargs = None
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
        self.__resp_headers.append(name, value)

    def set_headers(self, seq):
        self.__resp_headers += seq

    def initialize(self):
        """重写这个方法
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def handle(self):
        """重写这个方法,以添加自己的处理逻辑"""
        pass

    def __handle(self):
        if self.__is_start_response and not self.__is_response_header:
            stcode = int(self.__resp_status[0:3])
            self.__start_response(self.__resp_status, self.__resp_headers)
            if stcode not in (100, 101, 102,): self.__is_response_header = True
            return
        if self.__is_start_response and not self.request.recv_ok(): self.on_recv_stream()
        if self.__is_start_response and self.request.recv_ok(): self.handle()

    def __iter__(self):
        if not self.__continue: return self
        if not self.__is_finish: self.__handle()
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
        if not byte_data: return
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
