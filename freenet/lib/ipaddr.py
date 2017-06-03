#!/usr/bin/env python3
"""
分配与释放IP地址
"""

import socket
import freenet.lib.utils as utils


class IpaddrNoEnoughErr(Exception):
    """IP地址资源不够
    """
    pass


class ipalloc(object):
    __no_use_iplist = None
    __subnet = None
    __subnet_num = None
    __prefix = None
    __prefix_num = None

    __cur_max_ipaddr_num = None

    __is_ipv6 = None

    __fa = None

    def __init__(self, subnet, prefix, is_ipv6=False):

        self.__no_use_iplist_num = []
        self.__subnet = subnet
        self.__prefix = prefix
        self.__is_ipv6 = is_ipv6

        if not is_ipv6:
            self.__fa = socket.AF_INET
            self.__cur_max_ipaddr_num = utils.bytes2number(socket.inet_pton(socket.AF_INET, subnet))
            self.__prefix_num = utils.calc_net_prefix_num(prefix)
        else:
            self.__fa = socket.AF_INET6
            self.__cur_max_ipaddr_num = utils.bytes2number(socket.inet_pton(socket.AF_INET6, subnet))
            self.__prefix_num = utils.calc_net_prefix_num(prefix, is_ipv6=True)

        self.__subnet_num = self.__cur_max_ipaddr_num
        return

    def put_addr(self, byte_ip):
        n = utils.bytes2number(byte_ip)

        if n == self.__cur_max_ipaddr_num:
            self.__cur_max_ipaddr_num -= 1
            return
        self.__no_use_iplist_num.append(n)

    def get_addr(self):
        if self.__no_use_iplist: return self.__no_use_iplist.pop(0)
        size = 4
        if self.__is_ipv6: size = 16

        self.__cur_max_ipaddr_num += 1
        byte_ip = utils.number2bytes(self.__cur_max_ipaddr_num, size)

        if self.__cur_max_ipaddr_num & self.__prefix_num != self.__subnet_num:
            raise IpaddrNoEnoughErr("not enough ip address")

        return byte_ip
