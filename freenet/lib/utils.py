#!/usr/bin/env python3

import socket
import freenet.lib.checksum as checksum
import freenet.lib.fn_utils as fn_utils
import random

__IP_HDR_SIZE = 20


def build_ip_packet(pkt_len, protocol, saddr, daddr, message, pkt_id=1, flags_df=0, flags_mf=0, offset=0):
    """创建IP数据包
    :param pkt_len:包长度
    :param saddr: bytes类型的源地址
    :param daddr: bytes类型的目的地址
    :param message:消息内容
    :param pkt_id: 包ID
    :param flags_df: 分段df位
    :param flags_mf:分段mf位
    :param offset:包偏移
    :return ip_pkt:
    """
    if pkt_len < __IP_HDR_SIZE: raise ValueError("the value of pkt_len must be less than 20")
    if protocol < 0 or protocol > 255: raise ValueError("the value of protocol is wrong")

    tpl = b'E\x00\x00\x14\x00\x01\x00\x00@\x00z\xea\x00\x00\x00\x00\x00\x00\x00\x00'

    L = list(tpl)

    # 修改地址
    csum = (L[10] << 8) | L[11]
    csum = checksum.calc_checksum_for_ip_change(tpl[12:16], saddr, csum)
    csum = checksum.calc_checksum_for_ip_change(tpl[16:20], daddr, csum)
    L[12:16] = saddr
    L[16:20] = daddr

    # 修改包长度
    old_v = (L[2] << 8) | L[3]
    new_v = pkt_len
    csum = fn_utils.calc_incre_csum(csum, old_v, new_v)
    L[2:4] = ((pkt_len & 0xff00) >> 8, pkt_len & 0x00ff,)

    # 修改包ID
    old_v = (L[4] << 8) | L[5]
    new_v = pkt_id
    csum = fn_utils.calc_incre_csum(csum, old_v, new_v)
    L[4:6] = ((pkt_id & 0xff00) >> 8, pkt_id & 0x00ff,)

    # 修改flags以及offset
    old_v = (L[6] << 8) | L[7]
    new_v = (flags_df << 14) | (flags_mf << 13) | offset
    csum = fn_utils.calc_incre_csum(csum, old_v, new_v)
    L[6:8] = ((new_v & 0xff00) >> 8, new_v & 0x00ff,)

    # 修改协议
    old_v = L[9]
    new_v = protocol
    csum = fn_utils.calc_incre_csum(csum, old_v, new_v)
    L[9] = protocol

    # 修改校检和
    # L[10:12] = (0, 0,)
    # csum = fn_utils.calc_csum(bytes(L), 20)
    L[10:12] = ((csum & 0xff00) >> 8, csum & 0x00ff,)

    return b"".join((bytes(L), message,))


def build_udp_packet(saddr, daddr, sport, dport, message, mtu=1500):
    """构建UDP数据包"""
    if mtu > 1500 or mtu < 576: raise ValueError("the value of mtu is wrong!")
    msg_len = 8 + len(message)
    # 构建UDP数据头
    udp_hdr = (
        (sport & 0xff00) >> 8,
        sport & 0x00ff,
        (dport & 0xff00) >> 8,
        dport & 0x00ff,
        (msg_len & 0xff00) >> 8,
        msg_len & 0x00ff,
        0, 0,
    )
    pkt_data = b"".join(
        (bytes(udp_hdr), message,)
    )

    pkts = []
    flags_df = 0
    step = mtu - __IP_HDR_SIZE - (mtu - __IP_HDR_SIZE) % 8
    b = 0
    e = step
    pkt_id = random.randint(1, 65535)
    # pkt_id = 1
    n = 0
    every_offset = int(step / 8)

    while 1:
        bdata = pkt_data[b:e]
        slice_size = len(bdata)

        if e >= msg_len:
            finish = True
        else:
            finish = False

        if finish:
            flags_mf = 0
        else:
            flags_mf = 1

        offset = n * every_offset
        ippkt = build_ip_packet(slice_size + 20, 17,
                                saddr, daddr, bdata, pkt_id=pkt_id,
                                flags_df=flags_df, flags_mf=flags_mf,
                                offset=offset
                                )

        pkts.append(ippkt)
        if finish: break
        n += 1
        b = e
        e = b + step

    return pkts


def ip4b_2_number(ip_pkt):
    """ipv4 bytes转换为数字"""
    return (ip_pkt[0] << 24) | (ip_pkt[1] << 16) | (ip_pkt[2] << 8) | ip_pkt[3]


def ip4s_2_number(string):
    """ipv4 字符串转换为数字"""
    ip_pkt = socket.inet_aton(string)
    return ip4b_2_number(ip_pkt)
