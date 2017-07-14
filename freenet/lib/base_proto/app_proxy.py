# !/usr/bin/env python3
"""应用层代理协议,该协议加载在隧道协议之上
1.建立连接
    客户端请求如下报文:
        cookie_id:2bytes 客户端生成的cookie id
        cmd: 1 byte 同socks5 cmd,不支持BIND
        atyp:1byte 地址类型,同socks5 atyp,注意请求UDP代理时该值代表的IP地址类型,而且值不能为3
        addr_len: 1 byte地址长度
        port:2 bytes 客户端请求端口,如果为UDP代理那么该项可忽略
        address:请求地址,如果为UDP代理那么该项可忽略
    服务端响应如下:
        cookie_id:2 bytes 客户端给定的cookie id
        resp_code:1 byte 响应状态码,1表示成功,0表示失败

2.发送数据(客户端和服务端)
    TCP协议如下:
        cookie_id:2 bytes
        is_close:1 byte 是否关闭连接,0表示不关闭连接,1表示关闭连接,服务端忽略这个值,当改值为1时不能携带任何数据
        data:
    UDP协议如下
        cookie_id:2 bytes
        atyp:1 byte 地址类型
        addr_len:1 byte地址长度
        port:2 bytes 端口
        address:
        data:数据内容
"""

_REQ_FMT = "!HbbbH"
_REQ_RESP_FMT = "!Hb"

_TCP_DATA_SEND_FMT = "!Hb"
_UDP_DATA_SEND_FMT = "!HbbH"

import struct, socket


class ProtoErr(Exception): pass


def parse_reqconn(byte_data):
    size = len(byte_data)
    if size < 7: raise ProtoErr("wrong request protocol")

    cookie_id, cmd, atyp, addr_len, port = struct.unpack(_REQ_FMT, byte_data[0:7])

    if cmd not in (1, 3,): raise ProtoErr("wrong cmd value")
    if atyp not in (1, 3, 4,): raise ProtoErr("wrong atyp value")

    if addr_len + 7 < size: raise ProtoErr("wrong request protocol")

    if atyp == 1 and addr_len != 4: raise ProtoErr("wrong request protocol")
    if atyp == 4 and addr_len != 16: raise ProtoErr("wrong request protocol")
    if atyp == 3 and addr_len < 1: raise ProtoErr("wrong request protocol")

    is_ipv6 = False
    is_domain = False
    e = 7 + addr_len
    byte_host = byte_data[7:e]

    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, byte_host)
    elif atyp == 4:
        is_ipv6 = True
        host = socket.inet_ntop(socket.AF_INET6, byte_host)
    else:
        is_domain = True
        host = byte_host.decode("iso-8859-1")

    port = (byte_data[5] << 8) | byte_data[6]

    if port == 0: raise ProtoErr("wrong port value")

    return (is_ipv6, is_domain, cookie_id, cmd, host, port,)


def parse_respconn(byte_data):
    size = len(byte_data)
    if size < 3: raise ProtoErr("wrong protocol")

    cookie_id, resp_code = struct.unpack(_REQ_RESP_FMT, byte_data[0:3])

    return (cookie_id, resp_code)


def parse_tcp_data(byte_data):
    size = len(byte_data)
    if size < 4: raise ProtoErr("wrong protocol")

    cookie_id, is_close, = struct.unpack(_TCP_DATA_SEND_FMT, byte_data[0:3])

    return (cookie_id, is_close, byte_data[3:])


def parse_udp_data(byte_data):
    size = len(byte_data)
    if size < 8: raise ProtoErr("wrong protocol")

    cookie_id, atyp, addr_len, port = struct.unpack(_UDP_DATA_SEND_FMT, byte_data[0:6])

    if addr_len + 6 > size: raise ProtoErr("wrong protocol")
    if atyp not in (1, 3, 4,): raise ProtoErr("wrong atyp value")

    if atyp == 1 and addr_len != 4: raise ProtoErr("wrong request protocol")
    if atyp == 4 and addr_len != 16: raise ProtoErr("wrong request protocol")
    if atyp == 3 and addr_len < 1: raise ProtoErr("wrong request protocol")

    e = 6 + addr_len
    byte_host = byte_data[6:e]

    is_ipv6 = False
    is_domain = False

    if atyp == 1:
        host = socket.inet_ntop(socket.AF_INET, byte_host)
    elif atyp == 4:
        is_ipv6 = True
        host = socket.inet_ntop(socket.AF_INET6, byte_host)
    else:
        is_domain = True
        host = byte_host.decode("iso-8859-1")

    return (is_ipv6, is_domain, cookie_id, host, port, byte_data[e:],)


def build_reqconn(cookie_id, cmd, atyp, address, port):
    if atyp not in (1, 3, 4,): raise ProtoErr("wrong atyp value")
    if cmd not in (1, 3,): raise ProtoErr("wrong atyp value")

    if atyp == 1:
        addr_len = 4
        byte_addr = socket.inet_pton(socket.AF_INET, address)
    elif atyp == 4:
        addr_len = 16
        byte_addr = socket.inet_pton(socket.AF_INET6, address)
    else:
        addr_len = len(address)
        byte_addr = address.encode("iso-8859-1")

    byte_data = struct.pack(_REQ_FMT, cookie_id, cmd, atyp, addr_len, port)
    return b"".join([byte_data, byte_addr])


def build_respconn(cookie_id, resp_code):
    return struct.pack(_REQ_RESP_FMT, cookie_id, resp_code)


def build_tcp_send_data(cookie_id, byte_data, is_close=False):
    size = len(byte_data)
    fmt = "!Hb%ss" % size

    if is_close:
        close = 1
    else:
        close = 0

    if is_close and byte_data: raise ValueError("argument byte_data must be null")

    return struct.pack(fmt, cookie_id, close, byte_data)


def build_udp_send_data(cookie_id, atyp, address, port, byte_data):
    if atyp not in (1, 3, 4,): raise ProtoErr("wrong atyp value")

    if atyp == 1:
        addr_len = 4
        byte_addr = socket.inet_pton(socket.AF_INET, address)
    elif atyp == 4:
        addr_len = 16
        byte_addr = socket.inet_pton(socket.AF_INET6, address)
    else:
        addr_len = len(address)
        byte_addr = address.encode("iso-8859-1")

    header = struct.pack(_UDP_DATA_SEND_FMT, cookie_id, atyp, addr_len, port)

    return b"".join([header, byte_addr, byte_data])


"""
t = build_reqconn(0, 1, 1, "192.168.1.2", 8000)
print(parse_reqconn(t))
t = build_respconn(0, 1)
print(parse_respconn(t))

t = build_tcp_send_data(0, b"hello")
print(parse_tcp_data(t))

t = build_udp_send_data(0, 1, "192.168.1.2", 8800, b"hello")
print(t)
print(parse_udp_data(t))
"""
