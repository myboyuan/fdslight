#!/usr/bin/env python3
import socket
import freenet.lib.checksum as checksum


def build_udp_packet(saddr, daddr, sport, dport, message):
    msg_len = len(message)
    tot_len = msg_len + 20
    udp_len = msg_len + 8

    ip_hdr_list = [
        69, 0,
        (tot_len & 0xff00) >> 8,
        tot_len & 0x00ff,
        0, 1,
        0, 0,
        64, 17,
        0, 0,
    ]

    ip_hdr_list += list(socket.inet_aton(saddr))
    ip_hdr_list += list(socket.inet_aton(daddr))

    checksum.fill_ip_hdr_checksum(ip_hdr_list)
    # 不计算udp的校检和
    udp_hdr_list = (
        (sport & 0xff00) >> 8,
        sport & 0x00ff,
        (dport & 0xff00) >> 8,
        dport & 0x00ff,
        (udp_len & 0xff00) >> 8,
        udp_len & 0x00ff,
        0, 0,
    )

    pkt = b"".join(
        (
            bytes(ip_hdr_list), bytes(udp_hdr_list), message
        )
    )

    return pkt


def ip4b_2_number(ip_pkt):
    """ipv4 bytes转换为数字"""
    return (ip_pkt[0] << 24) | (ip_pkt[1] << 16) | (ip_pkt[2] << 8) | ip_pkt[3]


def ip4s_2_number(string):
    """ipv4 字符串转换为数字"""
    ip_pkt = socket.inet_aton(string)
    return ip4b_2_number(ip_pkt)
