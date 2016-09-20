#!/usr/bin/env python3

class jsonrpc_builder(object):
    __VERSION = "2.0"

    def build_call(self, method, params, rpc_id):
        pass

    def build_calls(self, seq):
        pass

    def build_return_error(self, error, code, message):
        pass

    def get_return(self):
        pass

    def get_call(self):
        pass


class jsonrpc_parser(object):
    pass


class rpc_builder(object):
    pass


class rpc_parser(object):
    pass
