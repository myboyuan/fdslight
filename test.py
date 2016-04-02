#!/usr/bin/env python3
import socket
import pywind.lib.timer as timer
import freenet.lib.file_parser as file_parser


def ip4b_2_number(ip_pkt):
    """ipv4 bytes转换为数字"""
    return (ip_pkt[0] << 24) | (ip_pkt[1] << 16) | (ip_pkt[2] << 8) | ip_pkt[3]


class _udp_whitelist(object):
    """UDP白名单类"""
    __tree = None
    # 缓存回收超时
    __CACHE_TIMEOUT = 180
    __timer = None

    __cache = None

    def __init__(self):
        self.__tree = {}
        self.__timer = timer.timer()
        self.__cache = {}

    def add_rule(self, ipaddr, mask):
        if mask < 1 or mask > 32: raise ValueError("the value of mask is wrong")
        ippkt = socket.inet_aton(ipaddr)

        tmp_dict = self.__tree

        a = int(mask / 8)
        r = mask % 8
        if r: a += 1

        for i in range(4):
            n = ippkt[i]

            if i + 1 == a:
                if "values" not in tmp_dict: tmp_dict["values"] = {}
                if mask not in tmp_dict["values"]: tmp_dict["values"][mask] = []
                tmp_dict["values"][mask].append(n)
                break

            if n not in tmp_dict:
                tmp_dict[n] = {}

            tmp_dict = tmp_dict[n]

        return

    def __add_to_cache(self, ippkt, from_wl=True):
        self.__cache[ippkt] = from_wl
        self.__timer.set_timeout(ippkt, self.__CACHE_TIMEOUT)

    def __get_subn(self, a_list, b):
        cnt = 24
        ret_v = 0

        for n in a_list:
            ret_v |= n << cnt
            cnt -= 8

        return ret_v | (b << cnt)

    def find(self, ippkt):
        if ippkt in self.__cache: return self.__cache[ippkt]

        tmp_dict = self.__tree
        t_net_v = ip4b_2_number(ippkt)

        values = []
        _values = None

        for n in ippkt:
            if n not in tmp_dict:
                if "values" not in tmp_dict:
                    self.__add_to_cache(ippkt, from_wl=False)
                    return False
                _values = tmp_dict["values"]
                break
            values.append(n)
            tmp_dict = tmp_dict[n]

        is_find = False

        for m in _values:
            mask_v = 0
            for i in range(m): mask_v |= 1 << (31 - i)
            for t in _values[m]:
                subn = self.__get_subn(values, t)
                if t_net_v & mask_v == subn:
                    is_find = True
                    break
                ''''''
            ''''''
        self.__add_to_cache(ippkt, from_wl=is_find)

        return is_find

    def recycle_cache(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__cache: del self.__cache[name]
            if self.__timer.exists(name): self.__timer.drop(name)
        return

    def print_tree(self):
        print(self.__tree)

