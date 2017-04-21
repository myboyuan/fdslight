#!/usr/bin/env python3
import pywind.lib.timer as timer
import freenet.lib.utils as utils


class ip6_dgram_proxy(object):
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
