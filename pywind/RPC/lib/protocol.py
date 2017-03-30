#!/usr/bin/env python3
"""
RPC通讯协议
"""

import json

#### 故障码大全

# 找不到命名空间
ERR_NO_NAMESPACE = 1

# 方法找不到
ERR_NO_METHOD = 2


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


def build_function_return(call_id, return_val=None, is_err=False, err_code=None):
    """构建函数返回值
    :param call_id: 
    :param return_val: 
    :param is_err:是否发生故障
    :param err_code:故障码
    :return: 
    """
    pydict = {
        "call_id": call_id,
        "return": return_val,
        "is_err": is_err,
        "err_code": err_code,
    }

    return json.dumps(pydict)


def parse_function_call(sts):
    pass


def parse_function_return(sts):
    pass
