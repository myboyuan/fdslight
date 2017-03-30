#!/usr/bin/env python3

import socket
import pywind.RPC.lib.protocol as rpc_protocol


class _namespace(object):
    pass


class _resource(object):
    __obj_id = None
    __func_name = None
    __sent_func = None

    def __init__(self, sent_func, object_id):
        self.__obj_id = object_id
        self.__sent_func = sent_func

    def __getattr__(self, item):
        self.__func_name = item

        return self

    def __call__(self, *args, **kwargs):
        return self.__sent_func(self.__func_name, *args, **kwargs)


class rpc_client(object):
    def get_ns(self, ns):
        """获取命名空间
        :param ns: 
        :return: 
        """
        pass

    def __send_request(self, func_name, *args, **kwargs):
        pass
