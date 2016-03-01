#!/usr/bin/env python3
import pywind.evtframework.handler.hhook.hook as hook_base
import pywind.lib.reader as reader
import pywind.web.lib.httpchunked as httpchunked
import os


class _wsgi_error(object):
    """WSGI故障流"""
    __log_dir = None

    def __init__(self, log_dir):
        self.__log_dir = log_dir

    def flush(self):
        pass

    def write(self, s):
        pass

    def writelines(self, seq):
        pass


class _wsgi_input(object):
    __reader = None

    def __init__(self, r):
        self.__reader = r

    def read(self, size=-1):
        return self.__reader.read(size)

    def readline(self, limit=-1):
        return self.__reader.readline(limit)

    def readlines(self, hint=None):
        return self.__reader.readlines(hint)

    def __iter__(self):
        return self

    def __next__(self):
        return self.__reader.readline()


class wsgi_hook(hook_base.hook):
    __application = None
    __config = None
    __hook_name = None
    __wsgi_input = None
    # 是否响应HTTP头
    __is_resp_header = False
    # 响应状态码
    __resp_status = None
    # 响应头
    __resp_headers = None
    # 已经读取的内容大小
    __read_size = 0
    # 总的内容大小
    __content_size = 0

    # 是否是块内容
    __is_chunked = False
    # chunk对象
    __chunked_parse = None

    # 响应的内容大小
    __resp_content_size = 0
    # 已经响应的内容大小
    __responsed_size = 0

    # 响应状态码
    __resp_stcode = 200

    def __start_response(self, status, headers, exc_info=None):
        # 是否有内容长度
        have_content_length = False
        is_chunked = False
        for k, v in headers:
            if k.lower() == "content-length":
                have_content_length = True
                self.__resp_content_size = int(v)
                break
            if k.lower() == "transfer-encoding" and v.lower() == "chunked":
                is_chunked = True
                break
        try:
            stcode = int(status[0:3])
        except ValueError:
            pass
        # 自动添加长度
        if stcode != 200 and not have_content_length:
            headers.append(("Content-Length", "0"))

        self.__resp_stcode = stcode
        self.__resp_status = status
        self.__resp_headers = headers
        self.__is_resp_header = False
        self.__is_chunked = is_chunked

        if is_chunked:
            self.__chunked_parse = httpchunked.parser()
        return

    def __is_finish(self):
        """响应是否结束"""
        if self.__is_chunked:
            return self.__chunked_parse.is_finish()

        return self.__resp_content_size == self.__responsed_size

    def __get_resp_body_data(self, byte_data):
        if not self.__is_chunked:
            n = self.__resp_content_size - self.__responsed_size
            resp_data = byte_data[0:n]
            data_len = len(resp_data)
            self.__responsed_size += data_len
            return resp_data

        self.__chunked_parse.add_data(byte_data)
        return self.__chunked_parse.get_chunked_entity()

    def __wsgi_run(self):
        for resp_body in self.__application:
            if resp_body and not self.__is_resp_header:
                self.handler_ctl(self.__hook_name, "resp_header", self.__resp_status, self.__resp_headers)
            body = self.__get_resp_body_data(resp_body)
            self.hook_output(self.__hook_name, body)

        if not self.__is_chunked and self.__resp_content_size == 0:
            self.handler_ctl(self.__hook_name, "resp_header", self.__resp_status, self.__resp_headers)

        if self.__is_finish():
            self.handler_ctl(self.__hook_name, "resp_finish")
            self.hook_delete()
        return

    def __wsgi_init(self, environ):
        for k, v in os.environ.items():
            environ[k] = v

        if "PATH_INFO" not in environ:
            path_info = "/"
            req_uri = environ.get("REQUEST_URI", "/")
            pos = req_uri.find("?")
            if pos > 0:
                path_info = req_uri[0:pos]
            else:
                path_info = req_uri
            environ["PATH_INFO"] = path_info

        self.__wsgi_input = reader.reader()
        environ["wsgi.input"] = _wsgi_input(self.__wsgi_input)

        app = self.__config["application"]
        self.__application = app(environ, self.__start_response, wsgi_ctl=self.wsgi_ctl)

    def hook_init(self, hook_name, config, cgi_env):
        """
        :param hook_name: HOOK名
        :param cgi_env: 标准CGI环境变量
        :return:
        """
        try:
            self.__content_size = int(cgi_env.get("CONTENT_LENGTH", "0"))
        except ValueError:
            cgi_env["CONTENT_LENGTH"] = "0"

        self.__resp_headers = None
        self.__resp_status = ""

        self.__config = config
        self.__hook_name = hook_name

        self.__wsgi_init(cgi_env)
        self.__wsgi_run()

    def hook_input(self, byte_data):
        # 丢弃多余的数据包
        if self.__read_size == self.__content_size:
            return
        # 如果响应不是1xx那么直接丢弃数据包
        if self.__resp_stcode > 199:
            return

        n = self.__content_size - self.__read_size
        rdata = byte_data[0:n]
        data_len = len(rdata)
        self.__read_size += data_len

        self.__wsgi_input._putvalue(rdata)
        self.__wsgi_run()

    def hook_delete(self):
        if hasattr(self.__application, "close"):
            self.__application.close()
        return

    def wake_up_for_writable(self):
        self.__wsgi_run()

    def wsgi_ctl(self, name, value):
        """控制WSGI的行为"""
        if name not in ("freq_mode", "sleep_mode"):
            return False
        # 使用频繁模式,即数据没有响应完毕会不断调用WSGI
        if name == "freq_mode":
            return self.handler_ctl(self.__hook_name, "freq_mode")

        # 安静模式,没有数据写入的时候,WSGI将不再被自动唤醒"""
        if name == "sleep_mode":
            return self.handler_ctl(self.__hook_name, "sleep_mode")

        return False
