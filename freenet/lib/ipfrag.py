#!/usr/bin/env python3
import pywind.lib.timer as timer
import freenet.lib.utils as utils
import socket


class ip4_p2p_proxy(object):
    """处理IPV4  UDP 或者 UDPLite PROXY的数据分包
    此类的作用是对数据进行组包
    """
    __frag_data = None
    __timer = None

    __ok_packets = None

    # 超时时间,超时就丢弃分包
    __TIMEOUT = 5

    def __init__(self):
        """
        :param max_size: 组包之后数据的最大大小,单位为字节
        """
        self.__frag_data = {}
        self.__timer = timer.timer()
        self.__ok_packets = []

    def add_frag(self, mbuf):
        mbuf.offset = 4
        byte_uniq_id = mbuf.get_part(2)

        mbuf.offset = 6
        frag_off = utils.bytes2number(mbuf.get_part(2))
        df = 0x4000 >> 14
        mf = 0x2000 >> 13
        offset = frag_off & 0x1fff

        mbuf.offset = 12
        saddr = mbuf.get_part(4)

        # 处理没有分包的情况
        if offset == 0 and mf == 0:
            saddr, daddr, sport, dport = self.__get_pkt_addr_info(mbuf)
            if dport == 0: return
            content = self.__get_transfer_content(mbuf)
            self.__ok_packets.append((saddr, daddr, sport, dport, content,))
            return

        # 限制分包数目
        if offset > 2048: return

        _id = b"".join([saddr, byte_uniq_id])
        if offset == 0:
            saddr, daddr, sport, dport = self.__get_pkt_addr_info(mbuf)
            if dport == 0: return
            content = self.__get_transfer_content(mbuf)

            self.__frag_data[_id] = (saddr, daddr, sport, dport, [content, ])
            self.__timer.set_timeout(_id, self.__TIMEOUT)

            return
        elif _id not in self.__frag_data:
            return

        else:
            content = self.__get_transfer_content(mbuf, is_off=True)
            _, _, frag_pkts = self.__frag_data[_id]
            frag_pkts.append(content)

        if mf != 0: return

        saddr, daddr, sport, dport, frag_pkts = self.__frag_data[_id]

        self.__ok_packets.append(saddr, daddr, sport, dport, b"".join(frag_pkts))
        self.__timer.drop(_id)

        del self.__frag_data[_id]

    def get_data(self):
        self.recycle()
        try:
            return self.__ok_packets.pop(0)
        except IndexError:
            return None

    def __get_pkt_addr_info(self, mbuf):
        """获取数据包的地址信息
        :param mbuf:
        :return:
        """
        mbuf.offset = 0
        n = mbuf.get_part(1)
        hdrlen = (n & 0x0f) * 4

        mbuf.offset = hdrlen + 2
        dport = utils.bytes2number(mbuf.get_part(2))
        mbuf.offset = hdrlen
        sport = utils.bytes2number(mbuf.get_part(2))

        mbuf.offset = 16
        daddr = mbuf.get_part(4)
        mbuf.offset = 12
        saddr = mbuf.get_part(4)

        return (socket.inet_ntoa(saddr), socket.inet_ntoa(daddr), sport, dport,)

    def __get_transfer_content(self, mbuf, is_off=False):
        """
        :param mbuf:
        :param is_off: 是否有偏移
        :return:
        """
        if is_off:
            mbuf.offset = self.__get_pkt_hdr_len(mbuf)
        else:
            mbuf.offset = self.__get_pkt_hdr_len(mbuf) + 8

        return mbuf.get_data()

    def __get_pkt_hdr_len(self, mbuf):
        mbuf.offset = 0
        n = mbuf.get_part(1)
        hdrlen = (n & 0x0f) * 4

        return hdrlen

    def recycle(self):
        uniq_ids = self.__timer.get_timeout_names()
        for uniq_id in uniq_ids:
            if not self.__timer.exists(uniq_id): continue
            self.__timer.drop(uniq_id)
            del self.__frag_data[uniq_id]
        return


class ip6_p2p_proxy(object):
    """处理IPv6 UDP 和 UDPLite数据分包
    """
    __ok_packets = None
    __timer = None
    __TIMEOUT = 5
    __fragdata = None

    def __init__(self):
        self.__ok_packets = []
        self.__timer = timer.timer()
        self.__fragdata = {}

    def add_frag(self, mbuf):
        mbuf.offset = 8
        saddr = mbuf.get_part(16)
        mbuf.offset = 24
        daddr = mbuf.get_part(16)
        mbuf.offset = 42

        frag_off = utils.bytes2number(mbuf.get_part(2))
        m_flag = frag_off & 1
        frag_off = frag_off >> 3

        mbuf.offset = 44
        frag_id = mbuf.get_part(4)

        if frag_off == 0 and m_flag == 0:
            sport, dport = self.__get_pkt_port_info(mbuf)
            mbuf.offset = 56
            self.__ok_packets.append((saddr, daddr, sport, dport, mbuf.get_data(),))
            return

        uniq_id = b"".join([saddr, frag_id, ])

        if frag_off == 0 and m_flag == 1:
            sport, dport = self.__get_pkt_port_info(mbuf)
            mbuf.offset = 56

            self.__fragdata[uniq_id] = (saddr, daddr, sport, dport, [mbuf.get_data()])
            self.__timer.set_timeout(uniq_id, self.__TIMEOUT)
            return

        if uniq_id not in self.__fragdata: return
        mbuf.offset = 48
        content = mbuf.get_data()

        saddr, daddr, sport, dport, data_list = self.__fragdata[uniq_id]
        data_list.append(content)

        if m_flag != 0: return

        self.__ok_packets.append(
            (saddr, daddr, sport, dport, b"".join(data_list))
        )

        self.__timer.drop(uniq_id)
        del self.__fragdata[uniq_id]

    def __get_pkt_port_info(self, mbuf):
        mbuf.offset = 48
        sport = utils.bytes2number(mbuf.get_part(2))
        mbuf.offset = 50
        dport = utils.bytes2number(mbuf.get_part(2))

        return (sport, dport,)

    def get_data(self):
        self.recycle()
        try:
            return self.__ok_packets.pop(0)
        except IndexError:
            return None

    def recycle(self):
        uniq_ids = self.__timer.get_timeout_names()
        for uniq_id in uniq_ids:
            if not self.__timer.exists(uniq_id): continue
            self.__timer.drop(uniq_id)
            del self.__fragdata[uniq_id]
        return
