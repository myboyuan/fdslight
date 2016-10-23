#!/usr/bin/env python3
import json

### error code

E_PARSE_ERROR = -32700
E_INVALID_REQUEST = -32600
E_NOT_FOUND_METHOD = -32601
E_INVALID_PARAMS = -32602
E_INTERNAL_ERROR = -32603

VERSION = "2.0"


class jsonrpcErr(Exception): pass


class jsonrpc_builder(object):
    __rpc_id = 0

    def __init__(self, rpc_id):
        self.__rpc_id = int(rpc_id)

    def build_call(self, method, *args, **kwargs):
        params = []
        if args: params = args
        if kwargs: params = kwargs
        pydict = {
            "rpc": VERSION,
            "method": str(method),
            "id": self.__rpc_id
        }
        pydict["params"] = params
        return pydict

    def build_return_ok(self, result):
        pydict = {
            "rpc": VERSION,
            "result": result,
            "id": self.__rpc_id
        }
        return pydict

    def build_return_error(self, code, message, data=None):
        pydict = {
            "rpc": VERSION,
            "error": {"code": int(code), "message": message, "data": data},
            "id": self.__rpc_id
        }
        return pydict


class jsonrpc_parser(object):
    __rpc_id = 0
    __is_return_error = False
    __is_call = False
    __is_return_ok = False

    def __init__(self, rpc_id):
        self.__rpc_id = int(rpc_id)

    def __check_call(self, pydict):
        if "params" not in pydict: return False
        params = pydict["params"]
        if not isinstance(params, list) and not isinstance(params, dict): return False

        return True

    def __check_return_error(self, pydict):
        error = pydict["error"]

        if "code" not in error: return False
        if "message" not in error: return False

        return True

    def __check_return_ok(self, pydict):
        return True

    def __check_conflict(self, pydict):
        cnt = 0
        names = ("method", "error", "result",)
        for name in names:
            if name in pydict: cnt += 1

        if cnt != 1: return False

        return True

    def parse(self, message):
        self.__reset()
        try:
            pydict = json.loads(message)
        except json.JSONDecoder:
            raise jsonrpcErr(message)

        if "rpc" not in pydict: raise jsonrpcErr(message)
        if "id" not in pydict: raise jsonrpcErr(message)

        if not self.__check_conflict(pydict): raise jsonrpcErr(message)

        try:
            rpc_version = float(pydict["rpc"])
        except ValueError:
            raise jsonrpcErr(message)

        if rpc_version != float(VERSION): raise jsonrpcErr("wrong rpc version:%s" % rpc_version)

        try:
            rpc_id = int(pydict["id"])
        except ValueError:
            raise jsonrpcErr(message)

        if rpc_id != self.__rpc_id: raise jsonrpcErr("wrong rpc id:%s" % rpc_id)

        if "method" in pydict:
            self.__is_call = True
            if not self.__check_call(pydict): raise jsonrpcErr(message)
            return pydict

        if "error" in pydict:
            self.__is_return_error = True
            if not self.__check_return_error(pydict): raise jsonrpcErr(message)
            return pydict

        if "result" in pydict:
            self.__is_return_ok = True
            if not self.__check_return_ok(pydict): raise jsonrpcErr(message)
            return pydict

        raise jsonrpcErr(message)

    def is_return_error(self):
        return self.__is_return_error

    def is_call(self):
        return self.__is_call

    def is_return_ok(self):
        return self.__is_return_ok

    def __reset(self):
        self.__is_call = False
        self.__is_return_error = False
        self.__is_return_ok = False

    def get_function_call(self, pydict):
        return (pydict["method"], (), {})

    def get_function_return(self, pydict):
        return pydict["result"]


class RPCNotFoundMethodErr(Exception):
    pass


class RPCInvalidParamsErr(Exception): pass


class func_call(object):
    __functions = None

    def __init__(self):
        self.__functions = {}
        self.__functions["::"] = {}

    def register_function(self, name, func, module=None):
        if not module:
            self.__functions["::"][name] = func
        else:
            self.__functions[module][name] = func
        return

    def call_func(self, name, params):
        module, func_name = self.__get_func(name)
        if not module: module = "::"

        try:
            mod_functions = self.__functions[module]
        except KeyError:
            raise RPCNotFoundMethodErr("cannot found module %s" % module)

        try:
            func = mod_functions[func_name]
        except KeyError:
            raise RPCNotFoundMethodErr("cannot found method %s" % func_name)

        result = None

        try:
            if isinstance(params, dict):
                result = func(**params)
            else:
                result = func(*params)
        except TypeError:
            raise RPCInvalidParamsErr("function %s params error" % name)
        return result

    def __get_func(self, name):
        pos = name.find("::")
        if pos < 0: return (None, name,)

        mod_name = name[0:pos]
        pos += 2

        return (mod_name, name[pos:])
