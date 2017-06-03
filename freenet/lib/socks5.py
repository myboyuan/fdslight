#!/usr/bin/env python3
import socket


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


def parse_request_and_udpdata(byte_data, is_udp=False):
    """地址请求解析
    :param byte_data:
    :return:
    """
    cmd = 0
    fragment = 0
    if not is_udp:
        ver = byte_data[0]
        if ver != 5: raise ProtocolErr("wrong socks version")

        try:
            cmd = byte_data[1]
        except IndexError:
            raise ProtocolErr("wrong socks protocol")

        if cmd not in (1, 2, 3,):
            raise ProtocolErr("wrong socks command")
    else:
        try:
            fragment = byte_data[2]
        except IndexError:
            raise ProtocolErr("wrong socks protocol")

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

    e = e + 1
    if is_udp:
        try:
            data = byte_data[e:]
        except IndexError:
            raise ProtocolErr("wrong socks protocol")
        if fragment > 127: raise ProtocolErr("wrong udp fragment number")
    else:
        data = b""

    try:
        if atyp == 1:
            sts_address = socket.inet_ntop(socket.AF_INET, address)
        if atyp == 4:
            sts_address = socket.inet_ntop(socket.AF_INET6, address)
    except:
        raise ProtocolErr("wrong ip address format")

    if atyp == 3:
        sts_address = address.decode("iso-8859-1")

    return (cmd, fragment, atyp, sts_address, dport, data,)


def build_response_and_udpdata(rep_frag, atyp, bind_addr, bind_port, udp_data=None):
    """构建连接响应
    :param rep_frag:
    :param atyp:
    :param bind_addr:
    :param bind_port:
    :param udp_data:如果该项不是None,那么程序自动判断为UDP数据包
    :return:
    """
    if atyp not in (1, 3, 4): raise ValueError("wrong atpy value")

    if atyp == 1:
        byte_bind_addr = socket.inet_pton(socket.AF_INET, bind_addr)
    if atyp == 3:
        byte_bind_addr = bind_addr.encode("iso-8859-1")
    if atyp == 4:
        byte_bind_addr = socket.inet_pton(socket.AF_INET6, bind_addr)

    if udp_data == None:
        seq = [
            5, rep_frag, 0, atyp,
        ]
    else:
        seq = [
            0, 0, rep_frag, atyp,
        ]

    res_seq = [bytes(seq)]
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

    if udp_data: res_seq.append(udp_data)

    return b"".join(res_seq)
