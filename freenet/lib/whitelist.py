#!/usr/bin/env python3
import pywind.lib.timer as timer
import socket


class whitelist(object):
    """UDP白名单类"""
    __prefix = None
    __subnets = None
    # 缓存回收超时
    __CACHE_TIMEOUT = 180
    __timer = None

    __cache = None

    def __init__(self):
        self.__timer = timer.timer()
        self.__cache = {}
        self.__prefix = ([], {})
        self.__subnets = {}

    def add_rule(self, ipaddr, prefix):
        if prefix < 1 or prefix > 32: raise ValueError("the value of prefix is wrong")
        msk_list, msk_map = self.__prefix

        if prefix not in msk_list:
            msk_list.append(int(prefix))
            msk_list.reverse()

        name = "%s/%s" % (ipaddr, prefix,)
        self.__subnets[name] = None
        if prefix not in msk_map:
            msk_map[prefix] = 1
        else:
            msk_map[prefix] += 1
        return

    def __add_to_cache(self, ippkt, from_wl=True):
        self.__cache[ippkt] = from_wl
        self.__timer.set_timeout(ippkt, self.__CACHE_TIMEOUT)

    def __calc_subnet(self, ipaddr, prefix):
        if prefix == 32: return ipaddr

        q = int(prefix / 8)
        r = prefix % 8

        byte_ipaddr = socket.inet_aton(ipaddr)
        results = list(bytes(4))

        results[0:q] = byte_ipaddr[0:q]
        v = 0
        for n in range(r + 1):
            if n == 0: continue
            v += 2 ** (8 - n)

        results[q] = results[q] = byte_ipaddr[q] & v
        return socket.inet_ntoa(bytes(results))

    def find(self, ippkt):
        if ippkt in self.__cache: return self.__cache[ippkt]
        is_find = False
        ipaddr = socket.inet_ntoa(ippkt)
        msk_list, _ = self.__prefix

        for prefix in msk_list:
            subnet = self.__calc_subnet(ipaddr, prefix)
            name = "%s/%s" % (subnet, prefix,)
            if name not in self.__subnets: continue
            is_find = True
            break

        self.__add_to_cache(ippkt, from_wl=is_find)
        return is_find

    def recycle_cache(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__cache: del self.__cache[name]
            if self.__timer.exists(name): self.__timer.drop(name)
        return

    def print_tree(self):
        print((self.__prefix, self.__subnets,))

    def delete(self, ipaddr, prefix):
        name = "%s/%s" % (ipaddr, prefix,)
        if name not in self.__subnets: return
        msk_list, msk_map = self.__prefix
        msk_map[prefix] -= 1

        if msk_map[prefix] == 0:
            msk_list.remove(prefix)
            del msk_map[prefix]
        del self.__subnets[name]
