#!/usr/bin/env python3
"""
处理IP碎片封包
用以支持需要碎片封包的机器,比如PS4
支持范围:
    库会忽略offset,即假设数据包是顺序发送的,不会顺序到达的数据包该库不支持
"""

import freenet.lib.fn_utils as fn_utils
import pywind.lib.timer as timer


class udp_fragment(object):
    """只支持UDP协议的IP碎片分包与组包"""
    # 碎片包
    __fragment_packets = None
    # 组装完成后的包
    __complete_packets = None

    __timer = None
    # 分包超时
    __FRAGMENT_TIMEOUT = 60

    def __init__(self):
        self.__packets = {}
        self.__complete_packets = []
        self.__timer = timer.timer()

    def __calc_checksum(self, tot_len):
        """组包后重新计算校检和"""
        return

    def __get_transfer_layper_data(self, pkt):
        """获取传输层的数据"""
        ihl = (pkt[0] & 0x0f) * 4
        data = pkt[ihl:]
        tot_len = (pkt[2] << 8) | pkt[3]
        data_len = tot_len - ihl

        return (data_len, data,)

    def __merge_packet(self, pkt_id, last_ip_header):
        """合并IP数据包
        :param last_ip_header:最后一个IP包的IP头部
        :return:
        """
        if pkt_id not in self.__fragment_packets: return b""

        transfer_data_seq = []
        ihl = (last_ip_header[0] & 0x0f) * 4
        tot_len = ihl
        seq = self.__fragment_packets[pkt_id]
        # 传输层数据长度
        transfer_len = 8

        for data_len, data in seq:
            transfer_data_seq.append(data)
            transfer_len += data_len

        tot_len += transfer_len
        # 更改标志和偏移
        old_csum = (last_ip_header[10] << 8) | last_ip_header[11]
        old_field = (last_ip_header[6] << 8) | last_ip_header[7]
        csum = fn_utils.calc_incre_csum(old_csum, old_field, 0)

        # 更改头部长度
        old_csum = csum
        old_field = (last_ip_header[2] << 8) | last_ip_header[3]
        csum = fn_utils.calc_incre_csum(old_csum, old_field, tot_len)

        transfer_data_seq.insert(0, last_ip_header)
        pkt = b"".join(transfer_data_seq)
        L = list(pkt)

        L[2:4] = ((tot_len & 0xff00) >> 8, tot_len & 0x00ff,)
        L[6:8] = (0, 0,)
        L[10:12] = ((csum & 0xff00) >> 8, csum & 0x00ff,)

        # 修改UDP数据长度
        b = ihl + 4
        e = b + 2

        L[b:e] = ((transfer_len & 0xff00) >> 8, transfer_len & 0x00ff,)

        # 校检和修改为0,不计算UDP校检和
        b = e
        e = b + 2
        L[b:e] = (0, 0,)

        return bytes(L)

    def add_data(self, pkt):
        pkt_id = (pkt[4] << 8) | pkt[5]
        flags = (pkt[6] & 0xe0) >> 5
        offset = ((pkt[6] & 0x1f) << 5) | pkt[7]
        flags_df = (flags & 0x2) >> 1
        flags_mf = flags & 0x1
        # 标志为1表示数据不需要分段
        if flags_df:
            self.__complete_packets.append(pkt)
            return

        if pkt_id not in self.__fragment_packets:
            self.__timer.set_timeout(pkt_id, self.__FRAGMENT_TIMEOUT)
            self.__fragment_packets[pkt_id] = []

        seq = self.__fragment_packets[pkt_id]
        seq.append(self.__get_transfer_layper_data(pkt))

        if flags_mf: return
        ihl = (pkt[0] & 0x0f) * 4
        # 把最后一个IP头部插入到首部
        n_pkt = self.__merge_packet(pkt_id, pkt[0:ihl])
        if not n_pkt: return

        self.__complete_packets.append(n_pkt)
        del self.__fragment_packets[pkt_id]

    def get_packet(self):
        try:
            return self.__complete_packets.pop(0)
        except IndexError:
            return b""
        ''''''

    def recycle_resouce(self):
        """回收资源,可能有些IP分包发送了一部分就没有再发送"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__fragment_packets: del self.__fragment_packets[name]
            self.__timer.drop(name)
        return
