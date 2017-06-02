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


def parse_request(byte_data, is_udp=False):
    """地址请求解析
    :param byte_data:
    :param is_udp
    :return:
    """
    ver = byte_data[0]
    if ver != 5: raise ProtocolErr("wrong socks version")

    try:
        cmd = byte_data[1]
    except IndexError:
        raise ProtocolErr("wrong socks protocol")

    if cmd not in (1, 2, 3,):
        raise ProtocolErr("wrong socks command")

    try:
        atyp = byte_data[3]
    except IndexError:
        raise ProtocolErr("wrong socks protocol")

    if atyp not in (1, 3, 4,):
        raise ProtocolErr("wrong address type of following address")

    if atyp in (1, 4,):
        if atyp == 1:
            n = 4
            e = 8
        else:
            n = 16
            e = 20

        try:
            address = byte_data[4:e]
        except IndexError:
            raise ProtocolErr("wrong address type of following address")

        size = len(address)
        if size != n:
            raise ProtocolErr("wrong ip address length")
    else:
        try:
            addr_len = byte_data[4]
        except IndexError:
            raise ProtocolErr("wrong ip address length")

        e = 5 + addr_len
        try:
            address = byte_data[5:e]
        except IndexError:
            raise ProtocolErr("wrong ip address length")

        if len(address) != addr_len:
            raise ProtocolErr("wrong ip address length")

    try:
        a, b = (e, e + 1,)
        dport = (byte_data[a] << 8) | byte_data[b]
    except IndexError:
        raise ProtocolErr("wrong socks protocol")

    return (atyp, address, dport,)


def build_response(rep, atyp, byte_bind_addr, bind_port):
    """构建连接响应
    :param rep:
    :param atyp:
    :param byte_bind_addr:
    :param bind_port:
    :return:
    """
    seq = [
        5, rep, 0, atyp,
    ]

    res_seq = [bytes(seq)]

    if atyp not in (1, 3, 4): raise ValueError("wrong atpy value")
    if not isinstance(byte_bind_addr, bytes):
        raise ValueError("byte_bind_addr must be bytes type")

    size = len(byte_bind_addr)

    if atyp == 1 and size != 4:
        raise ValueError("wrong address length")
    if atyp == 4 and size != 16:
        raise ValueError("wrong address length")

    if atyp == 3 and size > 255:
        raise ValueError("wrong address length")

    if atyp == 3:
        res_seq.append(bytes([size & 0xff, ]))

    res_seq.append(byte_bind_addr)
    res_seq.append(
        bytes(
            [(bind_port & 0xff00) >> 8, bind_port & 0xff]
        )
    )

    return b"".join(res_seq)
