#!/usr/bin/env python3
"""计算校检和
"""
import socket
import freenet.lib.fn_utils as fn_utils

FLAG_MODIFY_SRC_IP = 0
FLAG_MODIFY_DST_IP = 1

PROTO_TCP = 0
PROTO_UDP = 1

# 填充TCP头部校检和
FLAG_FILL_TCP_CSUM = 0
# 填充UDP头部校检和
FLAG_FILL_UDP_CSUM = 1


def modify_address(byte_ip, ip_packet_list, flags):
    """修改地址
    :param ip:
    :param ip_packet_list:list数据结构的IP包
    :param flags: 指明修改源IP,还是目的IP地址
    :return:
    """
    new_ip = byte_ip

    protocol = ip_packet_list[9]
    # TCP
    if protocol == 6:
        modify_tcpudp_checksum_for_ip_change(new_ip, ip_packet_list, 1, flags)
    # UDP
    if protocol == 17:
        modify_tcpudp_checksum_for_ip_change(new_ip, ip_packet_list, 0, flags)

    __modify_ip_packet_address(new_ip, ip_packet_list, flags)


def calc_checksum_for_ip_change(old_ip_packet, new_ip_packet, old_checksum):
    """ ip地址改变之后重新获取校检码
    :param old_ip_packet:
    :param new_ip_packet:
    :param old_checksum:
    :return:
    """
    final_checksum = old_checksum
    a = 0
    b = 1
    # tmpcsum = old_checksum

    for i in range(2):
        old_field = (old_ip_packet[a] << 8) | old_ip_packet[b]
        new_field = (new_ip_packet[a] << 8) | new_ip_packet[b]
        # final_checksum = checksum.calc_incre_checksum(final_checksum, old_field, new_field)
        final_checksum = fn_utils.calc_incre_csum(final_checksum, old_field, new_field)
        a = a + 2
        b = b + 2

    return final_checksum


def __modify_ip_packet_address(ip_packet, ip_packet_list, flags=0):
    """修改IP包地址
    :param ip_packet: 新的bytes类型的IP地址
    :param ip_packet_list: list类型的IP包
    :param flags: 0表示修改的是源地址,1表示修改的是目的地址
    :return:
    """
    if flags:
        a = 16
        b = 20
    else:
        a = 12
        b = 16

    old_checksum = (ip_packet_list[10] << 8) | ip_packet_list[11]

    old_ip_packet = ip_packet_list[a:b]
    checksum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, old_checksum)

    ip_packet_list[10:12] = (
        (checksum & 0xff00) >> 8,
        checksum & 0x00ff,
    )

    if flags:
        ip_packet_list[16:20] = ip_packet
    else:
        ip_packet_list[12:16] = ip_packet
    return


def modify_tcpudp_checksum_for_ip_change(ip_packet, ip_packet_list, proto, flags=0):
    """ IP改变的时候重新计算TCP和UDP的校检和
    :param ip_packet:
    :param ip_packet_list:
    :param proto: 0表示计算的UDP,1表示计算的TCP
    :param flags: 0 表示修改时的源地址,1表示修改的是目的地址
    :return:
    """
    if proto not in [0, 1]: return

    hdr_len = (ip_packet_list[0] & 0x0f) * 4

    if flags:
        a = 16
        b = 20
    else:
        a = 12
        b = 16

    old_ip_packet = ip_packet_list[a:b]
    if proto == 0:
        a = hdr_len + 6
    if proto == 1:
        a = hdr_len + 16

    b = a + 1
    old_checksum = (ip_packet_list[a] << 8) | ip_packet_list[b]
    # 如果旧的校检和为0,说明不需要进行校检和计算
    if old_checksum == 0: return
    checksum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, old_checksum)

    ip_packet_list[a] = (checksum & 0xff00) >> 8
    ip_packet_list[b] = checksum & 0x00ff


def fill_ip_hdr_checksum(pkt_list):
    """填充IP包头校检和
    :param pkt: 列表形式的IP数据包,比如[11,23,...]
    :return:
    """
    hdr_len = (pkt_list[0] & 0x0f) * 4
    checksum = fn_utils.calc_csum(bytes(pkt_list), hdr_len)

    pkt_list[10:12] = (
        (checksum & 0xff00) >> 8,
        checksum & 0x00ff,
    )
    return


def fill_tcpudp_hdr_checksum(pkt_list, flags):
    """填充tcp或者UDP头部校检和
    :param pkt: 列表形式的IP数据包,比如[11,23,...]
    """
    hdr_len = (pkt_list[0] & 0x0f) * 4
    tot_len = (pkt_list[2] << 8) | pkt_list[3]
    tcpudpl = tot_len - hdr_len

    a = (tcpudpl & 0xff00) >> 8
    b = tcpudpl & 0x00ff

    if flags == FLAG_FILL_TCP_CSUM:
        n = hdr_len + 12
        tcpudp_hdr_len = ((pkt_list[n] & 0xf0) >> 4) * 4
        proto = 6
        c = hdr_len + 16
    else:
        tcpudp_hdr_len = 8
        proto = 17
        c = hdr_len + 6

    d = c + 2
    e = hdr_len
    f = hdr_len + tcpudp_hdr_len

    hdr_tuple = (
        # 伪头部
        bytes(pkt_list[12:16]),
        bytes(pkt_list[16:20]),
        bytes((0, proto, a, b,)),
        # 真实的头部
        bytes(pkt_list[e:f])
    )

    checksum = fn_utils.calc_csum(b"".join(hdr_tuple), 12)
    pkt_list[c:d] = (
        (checksum & 0xff00) >> 8,
        checksum & 0x00ff,
    )
    return


def _calc_incre_checksum(old_checksum, old_field, new_field):
    """使用增量式计算校检和
    :param old_checksum: 2 bytes的旧校检和
    :param old_field: 2 bytes的旧的需要修改字段
    :param new_field: 2 bytes的新的字段
    :return:
        """
    chksum = (~old_checksum & 0xffff) + (~old_field & 0xffff) + new_field
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += (chksum >> 16)

    return (~chksum) & 0xffff


def _calc_checksum(pacekt, size):
    """计算校检和
    :param pacekt:
    :param size:
    :return:
    """
    checksum = 0
    a = 0
    b = 1
    while size > 1:
        checksum += (pacekt[a] << 8) | pacekt[b]
        size -= 2
        a += 2
        b += 2

    if size:
        checksum += pacekt[a]

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    return (~checksum) & 0xffff
