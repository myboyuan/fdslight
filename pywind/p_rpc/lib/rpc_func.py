#!/usr/bin/env python3

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

        if isinstance(params, dict):
            try:
                result = func(**params)
            except TypeError:
                raise RPCInvalidParamsErr("function %s params error" % name)
            return result

        result = func(*params)

        return result

    def __get_func(self, name):
        pos = name.find("::")
        if pos < 0: return (None, name,)

        mod_name = name[0:pos]
        pos += 2

        return (mod_name, name[pos:])
