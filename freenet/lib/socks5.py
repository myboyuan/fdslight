#!/usr/bin/env python3

class ProtocolErr(Exception):
    pass


def parse_handshake_request(byte_data):
    """客户端连接之后,发送的握手请求解析
    :param byte_data:
    :return:
    """
    size = len(byte_data)

    if size < 3: raise ProtocolErr("wrong handshake request")

    ver = byte_data[0]
    nmethods = byte_data[1]

    n = nmethods + 2

    if size < n: raise ProtocolErr("wrong handshake request")
    if ver != 5: raise ProtocolErr("wrong socks version")

    byte_data = byte_data[2:]
    seq = []

    for i in byte_data: seq.append(i)

    return seq


def build_handshake_response(method):
    return bytes([5, method])


def parse_request(byte_data):
    """地址请求解析
    :param byte_data:
    :return:
    """
    pass
