#!/usr/bin/env python3
"""
RPC通讯协议
数据头部如下:
token_id: 16 bytes token id用于验证用户是否允许访问
data_len:2 bytes  数据长度
"""

import json, hashlib
import pywind.lib.reader as reader

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
    """生成token id
    :param sts_list: 字符串列表
    :return: 
    """
    byte_sts = []
    for sts in sts_list:
        byte_sts.append(sts.encode("iso-8859-1"))

    m = hashlib.md5()
    m.update(b"".join(byte_sts))

    return m.digest()


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


def build_function_return(call_id, return_val=None, is_resource=False, is_err=False, err_code=None):
    """构建函数返回值
    注意:如果返回值为资源时,返回值只能为Unicode字符串,数字
    :param call_id: 
    :param return_val: 
    :param is_resource:是否是资源,比如文件,类对象这些需要保存状态的对象
    :param is_err:是否发生故障
    :param err_code:故障码
    :return: 
    """
    if is_resource:
        if not isinstance(return_val, int) and not isinstance(return_val, str):
            raise ProtocolErr("the return value must be string or int when it is resource")

    pydict = {
        "call_id": call_id,
        "return": return_val,
        "is_err": is_err,
        "err_code": err_code,
        "is_resource": is_resource
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


HDR_LENGTH = 18


class parser(object):
    __reader = None
    __is_parsed_header = False

    __content_length = 0
    __token_id = None
    __results = None

    def __init__(self):
        self.__is_parsed_header = False
        self.__reader = reader.reader()
        self.__results = []

    def put_data(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        if not self.__is_parsed_header:
            if self.__reader.size() < HDR_LENGTH:
                return
            self.__token_id = self.__reader.read(16)
            t = self.__reader.read(2)
            self.__content_length = (t[0] << 8) | t[1]
            self.__is_parsed_header = True

        if self.__reader.size() < self.__content_length: return

        self.__results.append(
            (self.__token_id, self.__reader.read(self.__content_length).decode())
        )
        self.__is_parsed_header = False

    def get_result(self):
        rs = None
        try:
            rs = self.__results.pop(0)
        except IndexError:
            pass
        return rs


class builder(object):
    __token_id = None

    def __init__(self, token_id):
        if len(token_id) != 16: raise ValueError("wrong token id length")
        self.__token_id = token_id

    def build_data(self, sts):
        byte_data = sts.encode()
        content_length = len(byte_data)

        return b"".join(
            [
                self.__token_id,
                bytes([(content_length & 0xff00) >> 8, content_length & 0xff, ]),
                byte_data
            ]
        )


"""
b = builder(gen_token_id("hello"))
rs = b.build_data("nihao")

p = parser()
p.put_data(rs)

while 1:
    p.parse()
    t = p.get_result()
    if not t: break
    print(t)
"""
