#!/usr/bin/env python3
import json

### error code

E_PARSE_ERROR = -32700
E_INVALID_REQUEST = -32600
E_NOT_FOUND_METHOD = -32601
E_INVALID_PARAMS = -32602
E_INTERNAL_ERROR = -32603


class jsonrpc_builder(object):
    __VERSION = "2.0"

    def build_call(self, rpc_id, method, params=None):
        pydict = {
            "jsonrpc": self.__VERSION,
            "method": str(method),
            "id": int(rpc_id)
        }
        if params: pydict["params"] = params

        return pydict

    def build_return(self, rpc_id, result):
        pydict = {
            "jsonrpc": self.__VERSION,
            "result": result,
            "id": int(rpc_id)
        }
        return pydict

    def build_return_error(self, rpc_id,code, message, data=None):
        pydict = {
            "jsonrpc": self.__VERSION,
            "error": {"code": int(code), "message": message, "data": data},
            "id": rpc_id
        }
        return pydict


class jsonrpc_parser(object):
    pass