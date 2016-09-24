#!/usr/bin/env python3

import socket, json
import pywind.jsonrpc.lib.sock_proto as socket_proto
import pywind.jsonrpc.lib.jsonrpc as jsonrpc


class rpc_module(object):
    __module_name = None
    __function = None
    __remote_call = None

    def __init__(self, remote_call, module=""):
        self.__module_name = module
        self.__remote_call = remote_call

    def __rpc__(self, *args, **kwargs):
        func = "%s::%s" % (self.__module_name, self.__function)

        return self.__remote_call(func, *args, **kwargs)

    def __getattr__(self, item):
        self.__function = item

        return self.__rpc__


class sock_rpc_client(object):
    __socket = None
    __js_parser = None
    __js_builder = None
    __sock_parser = None
    __sock_builder = None

    def __init__(self, address, is_ipv6=False, is_ssl=False, ssl_cert=None):
        if is_ipv6:
            self.__socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            self.__socket = socket.socket()
        self.__socket.connect(address)

        self.__sock_parser = socket_proto.parser()
        self.__sock_builder = socket_proto.builder()

    def __rpc_handshake(self):
        self.__js_parser = jsonrpc.jsonrpc_parser(0)
        self.__js_builder = jsonrpc.jsonrpc_builder(0)

    def get_module(self, mod_name=""):
        """获取函数命名空间"""
        return rpc_module(self.__remote_call, mod_name)

    def __remote_call(self, func_name, *args, **kwargs):
        pyobj = self.__js_builder.build_call(func_name, *args, **kwargs)
        sts = json.dumps(pyobj)

        byte_data = sts.encode()
        self.__socket.send(byte_data)

        return func_name
