#!/usr/bin/env python3

class RPCNotFoundMethodErr(Exception):
    pass

class RPCInvalidParamsErr(Exception):pass

class base_handler(object):
    def register_function(self, name, func, module=None):
        pass

    def func_exists(self, func_name):
        pass

    def call_func(self, func_name, params):
        pass

