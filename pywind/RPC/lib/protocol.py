#!/usr/bin/env python3
"""
RPC通讯协议
"""

import json


def build_function_call(call_id, namespace, func_name, *args, **kwargs):
    """构建RPC函数调用
    :param call_id:调用id,由客户端自己生成
    :param namespace: 
    :param func_name: 
    :param args: 
    :param kwargs: 
    :return: 
    """
    pydict = {
        "call_id": call_id,
        "namespace": namespace,
        "function": func_name,
        "args": args,
        "kwargs": kwargs
    }

    return json.dumps(pydict)


def build_function_return(call_id, return_val):
    """构建函数返回值
    :param call_id: 
    :param return_val: 
    :return: 
    """
    pydict = {
        "call_id": call_id,
        "return": return_val
    }

    return json.dumps(pydict)


def parse_function_call(sts):
    pass


def parse_function_return(sts):
    pass
