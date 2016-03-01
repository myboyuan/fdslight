#!/usr/bin/env python3
import io
import time

import pywind.evtframework.handler.hhook.hook as hook
import pywind.web.lib.ctl_cmd as ctl_cmd
import pywind.web.lib.exceptions as excpts


class http1x_hook(hook.hook):
    # HTTP的最大头大小
    __MAX_HEADER_SIZE = 4 * 1024
    # 是否已经解析了http请求头
    __parsed_header = False
    # 此连接的SSL是否打开
    __ssl_on = False
    # 系统配置文件
    __config = None
    __byte_io = None
    # http1x的升级协议处理
    # 值实例:{"websocket":hook_cls}
    __http1x_upgrade_protos = None
    # HTTP第一行的请求部分
    __request = None
    # HTTP头部分
    __request_kv = None
    __SERVER_TAG = "PWWS/1.0"

    __current_action = ctl_cmd.HK_DEFAULT

    def __redirect_to_https(self, ext_header=None):
        """重新定向到https
        :param ext_header:额外需要添加的扩展头
        :return:
        """
        pass

    def __check_http1x_hdr(self, kv):
        """检查http头是否合法
        :param kv:
        :return Boolean:True表示全部合法,False表示并不合法
        """
        if "host" not in kv:
            return False
        if "user-agent" not in kv:
            return False
        return True

    def __handle_body_stream(self, byte_data):
        """处理body数据流
        :param byte_data:
        :return:
        """
        pass

    def __get_current_gmt_date(self):
        """获取当前GMT时间
        :return:
        """
        gmtime = time.gmtime()

        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime)

    def __handle_http1x_hdr(self, byte_data):
        """处理http头部数据
        :param byte_data:
        :return:
        """
        self.__byte_io.write(byte_data)
        value = self.__byte_io.getvalue()
        length = len(value)

        find_pos = value.find(b"\r\n\r\n")

        self.__byte_io.close()
        self.__byte_io = None

        if find_pos < 5 and length > self.__MAX_HEADER_SIZE:
            raise excpts.RequestHeaderTooLongErr

        try:
            sts = value.decode("iso-8859-1")
        except UnicodeDecodeError:
            raise excpts.HttpProtoErr

        tmplist = sts.split("\r\n")
        first_line = tmplist.pop(0)

        if not first_line:
            raise excpts.HttpProtoErr

        kv = {}
        for s in tmplist:
            if not s:
                continue
            p = s.find(":")
            if p < 1:
                raise excpts.HttpProtoErr
            k = s[0:p].lower()
            p += 1
            v = s[p:]
            kv[k] = v.lstrip()

        tmplist = first_line.split(" ")
        n = 0
        for s in tmplist:
            if not s:
                tmplist.pop(n)
            n += 1
        request = tuple(tmplist)
        if len(request) != 3:
            raise excpts.HttpProtoErr

        a = find_pos + 4
        return (request, kv, byte_data[a:])

    def __get_upgrade_proto(self):
        va = self.__request_kv.get("connection", "")
        vb = self.__request_kv.get("upgrade", "")

        if va.lower() != "upgrade":
            return None

        upg_proto = vb.lower()
        if upg_proto not in self.__http1x_upgrade_protos:
            raise excpts.NotSupportUpgradeProtoErr("not found upgrade protocol %s" % vb)

        return (upg_proto, self.__http1x_upgrade_protos[upg_proto])

    def __response_http1x_hdr(self, status, seq):
        """响应HTTP 1x数据头部"""
        tmp_seq = ["HTTP/1.1 %s\r\n" % status, ]
        seq += [
            ("Server", self.__SERVER_TAG,)
            ("Date", self.__get_current_gmt_date(), )
        ]
        for m in seq:
            sts = "%s: %s\r\n" % m
        tmp_seq.append(sts)

        tmp_seq.append("\r\n")
        resp_hdr = "".join(tmp_seq).encode("iso-8859-1")
        self.hook_output("output", resp_hdr)

    def __response_http1x_body(self, body_data):
        """响应HTTP1x 数据实体"""
        self.hook_output("output", body_data)

    def __filter_http1x_response_hdr(self, seq):
        """过滤HTTP头部,过滤掉和服务器冲突的
        :param seq:
        :return:
        """
        filter_list = [
            "Date", "Server", "Via"
        ]
        ret_seq = []
        for k, v in seq:
            if k.lower() in filter_list:
                continue
            ret_seq.append((k, v,))

        return ret_seq

    def __get_upgrade_proto(self, kv):
        """ 获取升级协议
        :param kv:
        :return (Boolean,upgrade_proto_name):True表示协议需要升级，False表示协议不需要升级,upgrade_proto_name只有True的时候有效
        """
        return (False, None)

    def hook_init(self, config, ssl_on=False):
        self.__ssl_on = ssl_on
        self.__config = config
        self.__byte_io = io.BytesIO()
        self.__http1x_upgrade_protos = self.__config["http1x_upgrade_protos"]

    def hook_ctl(self, cmd, *args):
        if cmd not in (ctl_cmd.HK_RESP_HTTP_HEADER, ctl_cmd.HK_RESP_HTTP_BODY):
            return False

        if cmd == ctl_cmd.HK_RESP_HTTP_HEADER:
            status, resp_headers = args
            self.__response_http1x_hdr(status, resp_headers)

        if cmd == ctl_cmd.HK_RESP_HTTP_BODY:
            self.__current_action = cmd

        return True

    def hook_delete(self):
        if self.__byte_io:
            self.__byte_io.close()
        return

    def hook_input(self, byte_data):
        if self.__current_action == ctl_cmd.HK_RESP_HTTP_BODY:
            self.hook_output("output", byte_data)
            return

        if self.__parsed_header:
            self.__handle_body_stream(byte_data)
            return

        try:
            self.__request, self.__request_kv, data = self.__handle_http1x_hdr(byte_data)
        except excpts.RequestHeaderTooLongErr:
            self.__response_http1x_hdr("414 Request-URI Too Long", [])
            self.delete_hook_chain()
            return
        except excpts.HttpProtoErr:
            self.__response_http1x_hdr("400 Bad Request", [])
            self.delete_hook_chain()
            return

        # 只支持http/1.1版本
        if self.__request[2].lower() != "http/1.1":
            self.__response_http1x_hdr("505 HTTP Version Not Supported", [])
            self.delete_hook_chain()
            return

        self.__parsed_header = True
        self.__handle_body_stream(data)

    def reset(self):
        self.__parsed_header = False
        self.__byte_io = io.BytesIO()
