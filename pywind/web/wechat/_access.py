#!/usr/bin/env python3
import pywind.web.lib.httpclient as httpclient
import json


class AccessErr(Exception):
    pass


class access(object):
    __app_id = None
    __secret = None
    __httclient = None

    def __init__(self, appid, secret, ssl_on=False, is_ipv6=False):
        """
        :param appid:
        :param secret:
        :param ssl_on:
        :param is_ipv6:
        :param is_async:是否进行异步调用
        """
        self.__app_id = appid
        self.__secret = secret

        host = "api.weixin.qq.com"

        self.__httclient = httpclient.client(host, ssl_on=ssl_on, is_ipv6=is_ipv6)

    def get_response_data(self):
        while 1:
            if not self.__httclient.response_ok():
                self.__httclient.handle()
                continue
            break

        return self.__httclient.get_data()

    def request_token(self):
        path = "/cgi-bin/token"

        qs_seq = [
            ("grant_type", "client_credential"),
            ("appid", self.__app_id),
            ("secret", self.__secret),
        ]

        self.httpclient.request(
            "GET", path=path, qs_seq=qs_seq
        )

    def request_servers(self, access_token):
        path = "/cgi-bin/getcallbackip"
        qs_seq = [
            ("access_token", access_token)
        ]

        self.httpclient.request("GET", path=path, qs_seq=qs_seq)

    def get_token(self, async=False):
        """获取访问token
        :param async 是否为异步请求
        :return:
        """
        if not async: self.request_token()
        resp_data = self.get_response_data()
        sts = resp_data.decode("iso-8859-1")

        result = json.loads(sts)

        if "errcode" not in result: return (False, result,)

        return (True, result)

    def get_servers(self, access_token=None):
        """获取所有的微信服务器
        :param access_token 如果为None表示异步调用
        :return:
        """
        if access_token:
            self.request_servers(access_token)

        resp_data = self.get_response_data()
        sts = resp_data.decode("iso-8859-1")

        result = json.loads(sts)

        return result

    @property
    def httpclient(self):
        return self.__httclient

    def finish(self):
        """结束API调用
        :return:
        """
        self.httpclient.close()


cls = access("wx3e13a1db5fdf0b7d", "c842a09c8328b2d68ee213c8893fdee8",ssl_on=True)
is_err, result = cls.get_token()

if is_err: cls.finish()

token = result["access_token"]

print(cls.get_servers(token))
