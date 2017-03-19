#!/usr/bin/env python3
import pywind.lib.timer as timer


class nat66(object):
    """处理NAT66的分包
    """
    __timer = None

    __frag_info = None

    __TIMEOUT = 15

    def __init__(self):
        """
        :param limit_data_size: 限制数据在未分包前的大小,单位是字节
        """
        self.__timer = timer.timer()
        self.__frag_info = {}

    def add_frag(self, session_id, saddr, flow_label):
        self.__frag_info[flow_label] = (session_id, saddr,)
        self.__timer.set_timeout(flow_label, self.__TIMEOUT)

    def get_frag_info(self, flow_label):
        """获取分片信息
        :param flow_label:
        :return:
        """
        return self.__frag_info.get(flow_label, None)

    def recycle(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.__timer.drop(name)
            del self.__frag_info[name]
        return


class ip4_udp_proxy(object):
    """处理IPV4 UDP PROXY的数据分包
    """
    __max_size = 0
    __data = None
    __timer = None

    def __init__(self, max_size=8192):
        """
        :param max_size: 组包之后数据的最大大小,单位为字节
        """
        self.__max_size = max_size
        self.__data = {}
        self.__timer = timer.timer()

    def add_frag(self, session_id, mbuf):
        mbuf.offset = 12
        saddr = mbuf.get_part(4)

        offset = 0

        if offset == 0:
            pass

        if session_id not in self.__data:
            self.__data[session_id] = {}

        pydict = self.__data[session_id]

    def get_data(self):
        pass
