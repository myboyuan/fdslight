#!/usr/bin/env python3
"""
RPC通讯协议
数据头部如下:
token_id: 16 bytes token id用于验证用户是否允许访问
packet_type:1 bytes 包类型
data_len:2 bytes  数据长度
"""

import json, hashlib

#### 故障码大全

# 找不到命名空间
ERR_NO_NAMESPACE = 1

# 方法找不到
ERR_NO_METHOD = 2


class RPCErr(Exception):
    pass


class ProtocolErr(RPCErr):
    pass


class NsNotFoundErr(RPCErr):
    pass


class MethodNotFoundErr(RPCErr):
    pass


def gen_token_id(sts_list):
    pass



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


def parse_function_return(sts):
    try:
        pyobj = json.loads(sts)
    except json.JSONDecodeError:
        raise ProtocolErr

    fields = ["call_id", "return", "is_err", "err_code"]
    for name in fields:
        if name not in pyobj: raise ProtocolErr

    err_code = pyobj["err_code"]

    if pyobj["is_err"]:
        if err_code == ERR_NO_NAMESPACE:
            raise NsNotFoundErr
        if err_code == ERR_NO_METHOD:
            raise MethodNotFoundErr

    return pyobj


def parse_function_call(sts):
    try:
        pyobj = json.loads(sts)
    except json.JSONDecodeError:
        raise ProtocolErr

    fields = ["namespace", "call_id", "function", "args", "kwargs"]
    for name in fields:
        if name not in pyobj: raise ProtocolErr

    return pyobj
