#!/usr/bin/env python3
import freenet.lib.ipaddr as ipaddr
import pywind.lib.timer as timer
import freenet.lib.ippkts as ippkts


class _nat_base(object):
    # sesison ID到服务端虚拟出来的局域网的映射
    __sessionId2sLan = None
    # 服务端虚拟出来的局域网到客户端的局域网IP的映射
    __sLan2cLan = None

    def __init__(self):
        self.__sessionId2sLan = {}
        self.__sLan2cLan = {}

    def add2Lan(self, session_id, clan_addr, slan_addr):
        if session_id not in self.__sessionId2sLan: self.__sessionId2sLan[session_id] = {}
        t = self.__sessionId2sLan[session_id]
        t[clan_addr] = slan_addr

        if slan_addr not in self.__sLan2cLan: self.__sLan2cLan[slan_addr] = {}
        t = self.__sLan2cLan[slan_addr]
        t["session_id"] = session_id
        t["clan_addr"] = clan_addr

    def delLan(self, slan_addr):
        if slan_addr not in self.__sLan2cLan: return

        ta = self.__sLan2cLan[slan_addr]
        clan_addr = ta["clan_addr"]
        session_id = ta["session_id"]

        del self.__sLan2cLan[slan_addr]

        tb = self.__sessionId2sLan[session_id]
        del tb[clan_addr]
        if not tb: del self.__sessionId2sLan[session_id]

    def find_sLanAddr_by_cLanAddr(self, session_id, clan_addr):
        """根据客户端局域网中的IP找到服务端对应的局域网IP"""
        if session_id not in self.__sessionId2sLan: return None
        t = self.__sessionId2sLan[session_id]
        if clan_addr not in t: return None
        return t[clan_addr]

    def find_cLanAddr_by_sLanAddr(self, slan_addr):
        """根据服务端的虚拟局域网IP找到客户端对应的局域网IP"""
        if slan_addr not in self.__sLan2cLan: return None
        t = self.__sLan2cLan[slan_addr]

        return t

    def get_ippkt2sLan_from_cLan(self, session_id, ippkt):
        """重写这个方法
        把客户端局域网中的数据包转换成服务器虚拟局域网的包
        """
        return b""

    def get_ippkt2cLan_from_sLan(self, session_id, ippkt):
        """重写这个方法
        把服务端虚拟局域网中的包转换为客户端局域网中的数据包
        """
        return (bytes(16), b"",)

    def recycle(self):
        """回收资源,重写这个方法"""
        pass


class nat(_nat_base):
    __ip_alloc = None
    __timer = None
    # 映射IP的有效时间
    __VALID_TIME = 660
    __is_ipv6 = False

    def __init__(self, subnet, is_ipv6=False):
        super(nat, self).__init__()

        self.__is_ipv6 = is_ipv6
        self.__ip_alloc = ipaddr.ipalloc(*subnet, is_ipv6=is_ipv6)
        self.__timer = timer.timer()

    def get_ippkt2sLan_from_cLan(self, session_id, mbuf):
        if self.__is_ipv6:
            offset = 8
            size = 16
        else:
            offset = 12
            size = 4

        mbuf.offset = offset

        clan_saddr = mbuf.get_part(size)
        slan_saddr = self.find_sLanAddr_by_cLanAddr(session_id, clan_saddr)

        if not slan_saddr:
            try:
                slan_saddr = self.__ip_alloc.get_addr()
            except ipaddr.IpaddrNoEnoughErr:
                return False
            self.add2Lan(session_id, clan_saddr, slan_saddr)

        if not self.__is_ipv6:
            ippkts.modify_ip4address(slan_saddr, mbuf, flags=0)
        else:
            ippkts.modify_ip6address(slan_saddr, mbuf, flags=0)
        self.__timer.set_timeout(slan_saddr, self.__VALID_TIME)

        return True

    def get_ippkt2cLan_from_sLan(self, mbuf):
        if self.__is_ipv6:
            offset = 24
            size = 16
        else:
            offset = 16
            size = 4

        mbuf.offset = offset

        slan_daddr = mbuf.get_part(size)
        rs = self.find_cLanAddr_by_sLanAddr(slan_daddr)

        if not rs: return (False, None,)

        if not self.__is_ipv6:
            ippkts.modify_ip4address(rs["clan_addr"], mbuf, flags=1)
        else:
            ippkts.modify_ip6address(rs["clan_addr"], mbuf, flags=1)
        self.__timer.set_timeout(slan_daddr, self.__VALID_TIME)

        return (True, rs["session_id"],)

    def recycle(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            self.delLan(name)
            self.__ip_alloc.put_addr(name)
        return
