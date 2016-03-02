#!/usr/bin/env python3

import socket
import freenet.lib.checksum as checksum
import freenet.lib.fn_utils as fn_utils


def build_udp_packet(saddr, daddr, sport, dport, message):
    """构建UDP数据包"""
    # UDP模板
    tpl = b'E\x00\x00\x1c\x00\x01\x00\x00@\x11z\xd1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xde'
    msg_len = len(message)

    pkt_data = b"".join((tpl, message,))

    src_ippkt = socket.inet_aton(saddr)
    dst_ippkt = socket.inet_aton(daddr)

    L = list(pkt_data)

    # 修改源地址
    checksum.modify_address(src_ippkt, L, checksum.FLAG_MODIFY_SRC_IP)
    # 修改目的地址
    checksum.modify_address(dst_ippkt, L, checksum.FLAG_MODIFY_DST_IP)

    old_tot_len = (L[2] << 8) | L[3]
    old_csum = (L[10] << 8) | L[11]
    new_tot_len = old_tot_len + msg_len

    L[2:4] = ((new_tot_len & 0xff00) >> 8, new_tot_len & 0x00ff,)
    # 修改IP校检和
    csum = fn_utils.calc_incre_csum(old_csum, old_tot_len, new_tot_len)
    L[10:12] = ((csum & 0xff00) >> 8, csum & 0x00ff,)

    # 修改UDP内容长度
    old_csum = (L[26] << 8) | L[27]
    csum = fn_utils.calc_incre_csum(old_csum, old_tot_len, new_tot_len)
    L[26:28] = ((csum & 0xff00) >> 8, csum & 0x00ff,)


    new_udp_len = 8 + msg_len

    L[24:26] = ((new_udp_len & 0xff00) >> 8, new_udp_len & 0x00ff,)
    L[20:22] = ((sport & 0xff00) >> 8, sport & 0x00ff,)
    L[22:24] = ((dport & 0xff00) >> 8, dport & 0x00ff,)

    L[26:28] = (0, 0,)

    return bytes(L)


def ip4b_2_number(ip_pkt):
    """ipv4 bytes转换为数字"""
    return (ip_pkt[0] << 24) | (ip_pkt[1] << 16) | (ip_pkt[2] << 8) | ip_pkt[3]


def ip4s_2_number(string):
    """ipv4 字符串转换为数字"""
    ip_pkt = socket.inet_aton(string)
    return ip4b_2_number(ip_pkt)
