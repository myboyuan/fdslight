#!/usr/bin/env python3

import socket, json
import pywind.proc.lib.jsonrpc as jsrpc
import pywind.proc.lib.msg_socket as msg_socket


class _rpc_module(object):
    __func = None
    __module = None
    __callback = None

    def __init__(self, module, callback):
        self.__module = module
        self.__callback = callback

    def __getattr__(self, item):
        self.__func = item

        return self

    def __call__(self, *args, **kwargs):
        f = "%s%s" % (self.__module, self.__func,)

        return self.__callback(f, *args, **kwargs)


class rpcclient(object):
    __socket = None
    __parser = None
    __builder = None

    def __init__(self, family, address):
        self.__socket = socket.socket(family, socket.SOCK_STREAM)
        self.__socket = msg_socket.wrap_socket(self.__socket)
        self.__socket.connect(address)

        self.__parser = jsrpc.jsonrpc_parser()
        self.__builder = jsrpc.jsonrpc_builder()

    def get_module(self, module):
        return _rpc_module(module, self.__rpc_call)

    def __rpc_call(self, function, *args, **kwargs):
        pydict = self.__builder.build_call(function, *args, **kwargs)
        sent_data = json.dumps(pydict).encode("iso-8859-1")

        while 1:
            size = len(sent_data)
            sent_size = self.__socket.send(sent_data)
            if sent_size == size: break
            sent_data = sent_data[sent_size:]

        while 1:
            try:
                recv_data = self.__socket.recv(2048)
            except msg_socket.MsgSocketWantReadErr:
                continue
            break

        if self.__parser.is_call(): raise jsrpc.jsonrpcErr
        if self.__parser.is_return_error():
            return None

        sts = recv_data.decode("iso-8859-1")
        pydict = self.__parser.parse(sts)

        return self.__parser.get_function_return(pydict)
