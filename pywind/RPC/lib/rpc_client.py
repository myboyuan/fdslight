#!/usr/bin/env python3

import socket
import pywind.RPC.lib.protocol as rpc_protocol


class _namespace(object):
    pass


class _resource(object):
    __obj_id = None
    name = ""

    def __init__(self, sent_func, object_id):
        self.__obj_id = object_id

    def __getattr__(self, item):
        print(item)
