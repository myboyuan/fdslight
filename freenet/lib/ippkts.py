#!/usr/bin/env python3
"""计算校检和
"""
import freenet.lib.fn_utils as fn_utils
import freenet.lib.utils as utils
import random


def modify_ip4address(ip_packet, mbuf, flags=0):
    """
    :param ip_packet:
    :param mbuf:
    :param flags: 0表示修改源地址和端口,1表示修改目的地址和端口
    :return:
    """

    mbuf.offset = 9
    protocol = mbuf.get_part(1)

    if flags == 0:
        mbuf.offset = 12
    else:
        mbuf.offset = 16
    old_ip_packet = mbuf.get_part(4)
    mbuf.offset = 10
    csum = utils.bytes2number(mbuf.get_part(2))
    csum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, csum)
    mbuf.replace(utils.number2bytes(csum, 2))

    if protocol in (6, 17, 132, 136,):
        if protocol != 6:
            p = 1
        else:
            p = 0
        modify_tcpudp_for_change(ip_packet, mbuf, p, flags=flags)

    mbuf.offset = 10

    if flags == 0:
        mbuf.offset = 12
    else:
        mbuf.offset = 16

    mbuf.replace(ip_packet)


def modify_ip6address_for_nat66(ip_packet, ushort_number, mbuf, flags=0):
    """
    :param ip_packet:
    :param ushort_number:新分配的number,如果是分包,那么这个值任意
    :param mbuf:
    :param flags: 0表示修改源地址和端口,1表示修改目的地址和端口
    :return:
    """
    mbuf.offset = 6
    nexthdr = mbuf.get_part(1)

    if nexthdr == 58:
        modify_icmp6_echo_for_change(ip_packet, ushort_number, mbuf, flags=flags)

    if nexthdr in (6, 17, 132, 136,):
        if nexthdr == 6:
            p = 1
        else:
            p = 0
        modify_tcpudp_for_change(ip_packet, mbuf, p, flags=flags)

    if flags == 0:
        mbuf.offset = 8
    else:
        mbuf.offset = 24

    mbuf.replace(ip_packet)


def calc_checksum_for_ip_change(old_ip_packet, new_ip_packet, old_checksum, is_ipv6=False):
    """ ip地址改变之后重新获取校检码
    :param old_ip_packet:
    :param new_ip_packet:
    :param old_checksum:
    :param is_ipv6:是否是ipv6
    :return:
    """
    final_checksum = old_checksum
    a = 0
    b = 1
    # tmpcsum = old_checksum

    if is_ipv6:
        n = 8
    else:
        n = 2

    i = 0
    while i < n:
        old_field = (old_ip_packet[a] << 8) | old_ip_packet[b]
        new_field = (new_ip_packet[a] << 8) | new_ip_packet[b]
        # final_checksum = checksum.calc_incre_checksum(final_checksum, old_field, new_field)
        final_checksum = fn_utils.calc_incre_csum(final_checksum, old_field, new_field)
        a = a + 2
        b = b + 2
        i += 1

    return final_checksum


def modify_tcpudp_for_change(ip_packet, mbuf, proto, port=None, flags=0, is_ipv6=False):
    """ 修改传输层(SCTP,TCP,UDP,UDPLite,)内容
    :param ip_packet:
    :param ip_packet_list:
    :param proto: 0表示计算的UDP,SCTP以及UDPLITE,1表示计算的TCP
    :param port:端口为None那么不修改端口,如果为数字那么就会修改端口
    :param flags: 0 表示修改时的源地址,1表示修改的是目的地址
    :param is_ipv6:表示是否是否是IPV6
    :return:
    """
    if proto not in [0, 1]: return

    if is_ipv6:
        hdr_len = 40
    else:
        mbuf.offset = 0
        hdr_len = (mbuf.get_part(1) & 0x0f) * 4

    if flags:
        if is_ipv6:
            mbuf.offset = 24
        else:
            mbuf.offset = 16
        ''''''
    else:
        if is_ipv6:
            mbuf.offset = 8
        else:
            mbuf.offset = 12
        ''''''
    if is_ipv6:
        old_ip_packet = mbuf.get_part(16)
    else:
        old_ip_packet = mbuf.get_part(4)

    if proto == 0:
        n = hdr_len + 6
    else:
        n = hdr_len + 16

    mbuf.offset = n
    csum = utils.bytes2number(mbuf.get_part(2))
    # 如果旧的校检和为0,说明不需要进行校检和计算
    if csum == 0: return

    # 当端口不为None的时候,那么就修改端口
    if port != None:
        if flags == 0:
            mbuf.offset = hdr_len
        else:
            mbuf.offset = hdr_len + 2
        old_port = utils.bytes2number(mbuf.get_part(2))
        # 端口不一样那么更改端口
        if old_port != port:
            csum = fn_utils.calc_incre_csum(csum, old_port, port)
            mbuf.replace(utils.number2bytes(port, 2))
        ''''''
    csum = calc_checksum_for_ip_change(old_ip_packet, ip_packet, csum, is_ipv6=is_ipv6)
    mbuf.replace(utils.number2bytes(csum, 2))


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


def modify_icmp6_echo_for_change(byte_ip, new_icmpid, mbuf, flags=0):
    """修改ICMPv6报文
    :param byte_ip:
    :param new_icmpid:
    :param mbuf:
    :param flags:0表示修改请求报文,1表示表示修改响应报文
    :return:
    """
    mbuf.offset = 42
    csum = utils.bytes2number(mbuf.get_part(2))

    if flags == 0:
        mbuf.offset = 8
    else:
        mbuf.offset = 24

    old_byte_ip = mbuf.get_part(16)

    csum = calc_checksum_for_ip_change(old_byte_ip, byte_ip, csum, is_ipv6=True)

    mbuf.offset = 44
    icmpid = utils.bytes2number(mbuf.get_part(2))

    if icmpid != new_icmpid:
        csum = fn_utils.calc_incre_csum(csum, icmpid, new_icmpid)
        mbuf.replace(utils.number2bytes(new_icmpid, 2))

    mbuf.replace(utils.number2bytes(csum, 2))


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
    csum = calc_checksum_for_ip_change(tpl[12:16], saddr, csum)
    csum = calc_checksum_for_ip_change(tpl[16:20], daddr, csum)
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


def build_udp_packets(saddr, daddr, sport, dport, message, mtu=1500, is_udplite=False):
    """构建UDP数据包"""
    if mtu > 1500 or mtu < 576: raise ValueError("the value of mtu is wrong!")
    msg_len = 8 + len(message)
    # 构建UDP数据头
    udp_hdr = [
        (sport & 0xff00) >> 8,
        sport & 0x00ff,
        (dport & 0xff00) >> 8,
        dport & 0x00ff,
    ]

    if is_udplite:
        udp_hdr += [
            0, 8,
            0, 0,
        ]
        csum = fn_utils.calc_csum(bytes(udp_hdr))
        udp_hdr[6] = (csum & 0xff00) >> 8
        udp_hdr[7] = csum & 0xff
    else:
        udp_hdr += [
            (msg_len & 0xff00) >> 8,
            msg_len & 0x00ff,
            0, 0,
        ]

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

        if is_udplite:
            p = 136
        else:
            p = 17

        offset = n * every_offset
        ippkt = build_ip_packet(slice_size + __IP_HDR_SIZE, p,
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
