#!/usr/bin/env python3
import pywind.web.lib.exceptions as excpts
import urllib.parse, os, random
import pywind.web.lib.form as form
import pywind.web.lib.multipart as multipart


class _request(object):
    __environ = None
    __q_params = None
    __p_params = None

    __args = None
    __kwargs = None

    # 已经读取的数据大小
    __read_size = 0
    # 数据大小
    __content_size = 0

    __tmp_dir = None
    # 接收缓冲区
    __recv_buff = None
    __multipart = None
    # 临时文件名
    __tmp_filename = ""
    # 文件对象
    __tmp_fd = None

    def __init__(self, tmp_dir, environ, *args, **kwargs):
        """
        :param tmp_dir: 存放临时文件的目录
        :param environ: WSGI环境变量
        :param args: URL参数
        :param kwargs: 对应用的配置
        :return:
        """
        self.__environ = environ
        self.__q_params = None
        self.__p_params = None
        self.__args = args
        self.__kwargs = kwargs
        self.__content_size = int(self.__environ.get("CONTENT_LENGTH", "0"))
        self.__tmp_dir = tmp_dir
        self.__recv_buff = []
        self.__multipart = {}

    def __get_random_sts(self):
        """获取临时字符串"""
        sts = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_"
        length = len(sts)
        tmp_seq = []

        for i in range(8):
            n = random.randint(0, length - 1)
            tmp_seq.append(sts[n])

        return "".join(tmp_seq)

    def __get_tmp_fname(self):
        """获取临时文件名"""
        fname = ""
        while 1:
            fname = self.__get_random_sts()
            fpath = "%s/%s" % (self.__tmp_dir, fname)
            if os.path.isfile(fpath): continue
            break

        return fname

    @property
    def multipart(self):
        """获取mutipart上传信息"""
        return self.__multipart

    @property
    def environ(self):
        return self.__environ

    @property
    def p_params(self):
        """获取urlencoded数据"""
        if self.__p_params != None: return self.__p_params

        content_type = self.__environ.get("CONTENT_TYPE", "")

        if form.get_form_type(content_type) != form.FORM_URLENCODED: return

        self.__p_params = urllib.parse.parse_qs(b"".join(self.__recv_buff).decode())

        return self.__p_params

    @property
    def q_params(self):
        """获取QUERY_STRING"""
        if self.__q_params != None:
            return self.__q_params
        qs = self.__environ.get("QUERY_STRING", "")
        self.__q_params = urllib.parse.parse_qs(qs)

        return self.__q_params

    @property
    def args(self):
        """获取URL匹配结果"""
        return self.__args

    @property
    def kwargs(self):
        """获取路由配置传递的参数"""
        return self.__kwargs

    def read_size(self):
        """获取已经读取的数据大小"""
        return self.__read_size

    def raw_body(self):
        """获取没有加工过的body数据,只针对PUT方法有效"""
        return b"".join(self.__recv_buff)

    def _is_ok(self):
        """请求是否完成"""
        return self.__read_size == self.__content_size

    def __get_in_data(self):
        """获取输入流的数据"""
        bin_data = self.__environ["wsgi.input"].read()
        n_read = self.__content_size - self.__read_size
        bin_data = bin_data[0:n_read]
        data_len = len(bin_data)
        self.__read_size += data_len

        return bin_data

    def __handle_get_m(self):
        """处理GET方法"""
        pass

    def __handle_post_m(self):
        """处理POST方法"""
        content_type = self.__environ.get("CONTENT_TYPE", "")

        if form.get_form_type(content_type) != form.FORM_MULTIPART:
            bin_data = self.__get_in_data()
            self.__recv_buff.append(bin_data)
            return

        if not self.__tmp_fd:
            fname = self.__get_tmp_fname()
            self.__tmp_filename = fname
            fpath = "%s/%s" % (self.__tmp_dir, fname)
            self.__tmp_fd = open(fpath, "rwb")

        write_data = self.__get_in_data()
        self.__tmp_fd.write(write_data)

        if not self._is_ok():
            return

        fpath = "%s/%s" % (self.__tmp_dir, self.__tmp_filename)
        self.__tmp_fd.close()
        self.__tmp_fd = open()
        mparser = multipart.parser(form.get_multipart_boundary(content_type), self.__tmp_fd)

        while mparser.is_eof() == False:
            if not mparser.part_is_eof():
                continue
            name, mpblock = mparser.get_multipart_block()
            if name not in self.__multipart:
                self.__multipart[name] = []
            self.__multipart[name].append(mpblock)
        return

    def __handle_put_m(self):
        """处理PUT方法"""
        bin_data = self.__get_in_data()
        self.__recv_buff.append(bin_data)

    def __handle_delete_m(self):
        """处理DELETE方法"""
        pass

    def _handle(self):
        if self._is_ok():
            # 丢弃多余的数据包
            self.__environ["wsgi.input"].read()
            return

        method = self.__environ["REQUEST_METHOD"].upper()

        if method == "GET":
            self.__handle_get_m()
            return
        if method == "POST":
            self.__handle_post_m()
            return
        if method == "PUT":
            self.__handle_delete_m()
            return
        if method == "DELETE":
            self.__handle_delete_m()
            return

    def _cleanup(self):
        pass


class base_handler(object):
    __resp_headers = None
    __request = None
    __start_response = None
    # 是否开始响应
    __is_start_response = False

    MAX_POST_SIZE = 2 * 1024 * 1024

    # 是否继续执行
    __if_continue = True
    # 要发送的数据
    __sent = None
    __is_finish = False
    # 是否是chunk响应
    __is_chunk_resp = False
    __async_func = None
    # 是否调用过self.handle()函数
    __is_call_handle_func = False

    # 是否需要设置内容长度
    __need_set_content_length = True
    # 是否发生错误
    __error = False
    __wsgi_ctl = None

    def __init__(self, environ, start_response, wsgi_ctl, args, kwargs):
        self.__start_response = start_response
        self.__resp_headers = []
        self.__sent = []
        self.__request = _request("", environ, *args, *kwargs)
        self.__if_continue = self.init()
        self.__wsgi_ctl = wsgi_ctl
        self.__error = self.__check() == False

    def __next__(self):
        if self.__is_finish and not self.__sent:
            raise StopIteration

        if not self.__sent:
            raise StopIteration

        return self.__sent.pop(0)

    def __iter__(self):
        if self.__error:
            self.request.environ["wsgi.input"].read()
            return self

        if not self.__if_continue:
            self.request.environ["wsgi.input"].read()
            return self
        if self.request._is_ok():
            self.handle()
            self.__is_call_handle_func = True
        if not self.__async_func:
            return self
        func, args, kwargs = self.__async_func
        func_ret = func(*args, **kwargs)
        if not func_ret:
            self.__async_func = None
        return self

    def __check_form(self):
        """进行表单提交的检查"""
        content_type = self.environ["CONTENT_TYPE"]
        if form.get_form_type(content_type) == form.FORM_UNKOWN: return False

        return True

    def __check(self):
        """请求初始化时一些合法化检查"""
        req_method = self.request.environ["REQUEST_METHOD"].upper()
        content_length = int(self.request.environ["CONTENT_LENGTH"])
        check_rs = True
        # 表单合法化检查
        if req_method == "POST": check_rs = self.__check_form()
        # 表单检查不通过的处理办法
        if not check_rs:
            self.response("400 Bad Request")
            self.finish()
            return False
        # 检查POST大小,注意针对multipart是无效的,在multipart模式中应该手动检查
        if req_method == "POST" and content_length > self.MAX_POST_SIZE:
            print("B")
            self.response("413 Request Entity Too Large")
            self.finish()
            return False
        # 只允许一下四种请求方法
        if req_method not in ("POST", "GET", "PUT", "DELETE"):
            self.set_header("Allow", "GET,POST,PUT,DELETE")
            self.response("405 Method Not Allowed")
            self.finish()
            return False

        return True

    @property
    def request(self):
        return self.__request

    def handle_request_data(self):
        """处理请求数据,可以根据需要重写这个方法"""
        self.request._handle()

    def finish(self, byte_data=None):
        if self.__is_chunk_resp and byte_data:
            self.write_chunk(byte_data)
            self.write_chunk(b"")
        if self.__is_finish:
            raise excpts.WebAppError("you can not call this function more than 1 time")
        if not self.__is_chunk_resp and byte_data and self.__need_set_content_length:
            self.set_header("Content-Length", len(byte_data))
        if byte_data and not self.__is_chunk_resp:
            self.__sent.append(byte_data)
        self.__is_finish = True

    def write_chunk(self, byte_data):
        self.__is_chunk_resp = True
        data_size = len(byte_data)
        seq = [
            hex(data_size)[2:].encode("iso=8859-1"),
            b"\r\n",
            byte_data,
            b"\r\n"
        ]
        self.__sent.append(b"".join(seq))

    def write(self, byte_data):
        """使用此函数需要自己设置 Content-Length """
        self.__need_set_content_length = False
        self.__sent.append(byte_data)

    def response(self, status):
        self.__start_response(status, self.__resp_headers)
        self.__resp_headers = []

    def set_header(self, name, value):
        self.__resp_headers.append((name, value,))

    def set_headers(self, seq):
        self.__resp_headers += seq

    def redirect(self, url, status=302):
        pass

    def init(self):
        return True

    def handle(self):
        """重写这个方法
        :return:
        """
        pass

    def set_aysnc_func(self, func, *args, **kwargs):
        """设置异步函数
        func返回True表示继续异步调用,False表示结束异步调用
        """
        self.__async_func = (func, args, kwargs)
        self.__wsgi_ctl("freq_mode", None)

    def close(self):
        self.cleanup()

    def cleanup(self):
        """用于释放资源,重写这个方法"""
        pass


class staticfile(base_handler):
    """
    示例URL:r"^/static/([A-Za-z0-9_\-]+)$"
    """
    __mime_map = {
        "js": "application/x-javascript;charset=utf-8",
        "css": "text/css;charset=utf-8",
        "png": "image/png",
        "gif": "image/gif",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "ico": "image/x-icon",
        "svg": "image/svg+xml",
    }

    # 每次读取文件的大小
    __BLOCK_SIZE = 2 * 1024 * 1024
    __file_fd = None
    __file_path = ""
    __file_type = ""
    __file_size = 0

    def __get_file_ext_name(self, sts):
        """获取文件的扩展名"""
        tmplist = sts.split(".")
        size = len(tmplist)
        if size < 2:
            return None
        n = size - 1

        return tmplist[n].lower()

    def __update_mime_map(self, extra_map):
        """更新MIME映射,以支持更多MIME"""
        for k in extra_map:
            self.__mime_map[k] = extra_map[k]
        return

    def __async_response_file_stream(self):
        """异步响应静态文件"""
        if self.__file_fd:
            bin_data = self.__file_fd.read(self.__BLOCK_SIZE)
            self.write(bin_data)
            if self.__file_size - 1 > self.__file_fd.tell():
                return True
            self.__file_fd.close()
            self.__file_fd = None
            self.finish()
            return False

        self.__file_fd = open(self.__file_path, "rb")
        file_stat = os.stat(self.__file_path)
        fsize = file_stat.st_size
        self.__file_size = fsize

        self.set_headers(
            [
                ("Content-Type", self.__file_type),
                ("Content-Length", str(fsize))
            ]
        )
        self.response("200 OK")
        return True

    def init(self):
        # 只允许GET方法
        if self.request.environ["REQUEST_METHOD"].upper() == "GET":
            return True

        self.set_header("Allow", "GET")
        self.response("405 Method Not Allowed")

        return False

    def handle(self):
        # 静态文件目录
        part_path = self.request.args[0]
        static_dir = self.request.kwargs.get("static_dir", "./")

        # 获取自己定义的MIME MAP
        extra_mime = self.request.kwargs.get("mime", {})
        self.__update_mime_map(extra_mime)

        fpath = "%s/%s" % (static_dir, part_path)

        if not os.path.isfile(fpath):
            self.response("404 Not Found")
            self.finish()
            return

        ext_name = self.__get_file_ext_name(part_path)

        if ext_name not in self.__mime_map:
            self.response("403 Forbidden")
            self.finish()
            return

        self.__file_path = fpath
        self.__file_type = self.__mime_map[ext_name]
        self.set_aysnc_func(self.__async_response_file_stream)

    def cleanup(self):
        if self.__file_fd:
            self.__file_fd.close()
        return
