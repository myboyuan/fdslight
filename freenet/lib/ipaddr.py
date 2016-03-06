#!/usr/bin/env python3
"""
分配与释放IP地址
"""

import socket


class IpaddrNoEnoughErr(Exception):
    """IP地址资源不够
    """
    pass


class ip4addr(object):
    __base_ipaddr = 0
    __mask = 0
    __recycle_ips = None
    # 当前最大IP地址
    __current_max_ipaddr = 0

    def __init__(self, ipaddr, mask_size):
        """
        :param ipaddr:192.168.1.0
        :param mask:25
        :return:
        """
        self.__base_ipaddr = ipaddr
        self.__recycle_ips = []

        if mask_size < 1:
            raise ValueError("the mask_size must be number and the value must be more than 0")

        if mask_size > 31:
            raise ValueError("the mask_size must be number and the value must be less than 32")

        for i in range(mask_size):
            n = 32 - i
            self.__mask |= 1 << n

        self.__base_ipaddr = self.__get_int_ipaddr_from_sIpaddr(ipaddr)

        return

    def __get_int_ipaddr_from_sIpaddr(self, ipaddr):
        nbytes = socket.inet_aton(ipaddr)

        return (nbytes[0] << 24) | (nbytes[1] << 16) | (nbytes[2] << 8) | nbytes[3]

    def get_addr(self):
        """获取IP地址
        :param addr:
        :return:
        """
        if len(self.__recycle_ips) > 20:
            return self.__recycle_ips.pop(0)

        n = self.__current_max_ipaddr + 1
        host_n = self.__base_ipaddr & self.__mask

        if host_n < n:
            if self.__recycle_ips:return self.__recycle_ips.pop(0)
            raise IpaddrNoEnoughErr

        new_int_ip = self.__base_ipaddr + n
        self.__current_max_ipaddr = n

        a = (new_int_ip & 0xff000000) >> 24
        b = (new_int_ip & 0x00ff0000) >> 16
        c = (new_int_ip & 0x0000ff00) >> 8
        d = new_int_ip & 0x000000ff

        return bytes([a, b, c, d])

    def put_addr(self, ipaddr):
        """回收IP资源
        :param ipaddr:
        :return:
        """
        if ipaddr not in self.__recycle_ips:
            self.__recycle_ips.append(ipaddr)

        return
