#!/usr/bin/env python3
"""
处理IP碎片封包
"""

import pywind.lib.timer as timer
import socket


class parser(object):
    """只支持UDP协议的IP碎片分包与组包"""
    # 碎片包
    __fragment_packets = None
    # 组装完成后的包
    __complete_packets = None

    __timer = None
    # 分包超时
    __FRAGMENT_TIMEOUT = 60

    def __init__(self):
        self.__fragment_packets = {}
        self.__complete_packets = []
        self.__timer = timer.timer()

    def __get_transfer_layper_data(self, pkt):
        """获取传输层的数据"""
        ihl = (pkt[0] & 0x0f) * 4
        data = pkt[ihl:]

        return data

    def __get_ip_header(self, pkt):
        ihl = (pkt[0] & 0x0f) * 4
        data = pkt[0:ihl]

        return data

    def __parse_ip_header(self, ip_header):
        src_addr = socket.inet_ntoa(ip_header[12:16])
        dst_addr = socket.inet_ntoa(ip_header[16:20])

        return (src_addr, dst_addr,)

    def __parse_udp_header(self, udp_header):
        sport = (udp_header[0] << 8) | udp_header[1]
        dport = (udp_header[2] << 8) | udp_header[3]

        return (sport, dport,)

    def __merge_fragment_packet(self, pkt_id, ip_header):
        """合并IP数据包
        :param last_ip_header:最后一个IP包的IP头部
        :return:
        """
        seq = self.__fragment_packets[pkt_id]
        udp_data = b"".join(seq)

        src_addr, dst_addr = self.__parse_ip_header(ip_header)
        sport, dport = self.__parse_udp_header(udp_data[0:8])

        return (src_addr, dst_addr, sport, dport, udp_data[8:],)

    def __parse_no_slice_packet(self, pkt):
        ip_header = self.__get_ip_header(pkt)
        udp_data = self.__get_transfer_layper_data(pkt)

        src_addr, dst_addr = self.__parse_ip_header(ip_header)
        sport, dport = self.__parse_udp_header(udp_data[0:8])

        return (src_addr, dst_addr, sport, dport, udp_data[8:],)

    def add_data(self, pkt):
        pkt_id = (pkt[4] << 8) | pkt[5]
        flags = (pkt[6] & 0xe0) >> 5
        # offset = ((pkt[6] & 0x1f) << 5) | pkt[7]
        flags_df = (flags & 0x2) >> 1
        flags_mf = flags & 0x1

        if flags_df or (not self.__pkt_exists(pkt_id) and flags_mf == 0):
            result = self.__parse_no_slice_packet(pkt)
            self.__complete_packets.append(result)
            return

        if pkt_id not in self.__fragment_packets:
            self.__timer.set_timeout(pkt_id, self.__FRAGMENT_TIMEOUT)
            self.__fragment_packets[pkt_id] = []

        seq = self.__fragment_packets[pkt_id]
        seq.append(self.__get_transfer_layper_data(pkt))

        if flags_mf: return

        ihl = (pkt[0] & 0x0f) * 4
        result = self.__merge_fragment_packet(pkt_id, pkt[0:ihl])
        self.__complete_packets.append(result)

        del self.__fragment_packets[pkt_id]

    def get_packet(self):
        try:
            return self.__complete_packets.pop(0)
        except IndexError:
            return None
        ''''''

    def recycle_resouce(self):
        """回收资源,可能有些IP分包发送了一部分就没有再发送"""
        names = self.__timer.get_timeout_names()
        for name in names:
            print("delete")
            if name in self.__fragment_packets: del self.__fragment_packets[name]
            self.__timer.drop(name)
        return

    def __pkt_exists(self, pkt_id):
        return pkt_id in self.__fragment_packets
