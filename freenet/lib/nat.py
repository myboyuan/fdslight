#!/usr/bin/env python3
import freenet.lib.checksum as checksum
import freenet.lib.ipaddr as ipaddr
import pywind.lib.timer as timer


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
    __VALID_TIME = 900

    def __init__(self, subnet):
        super(nat, self).__init__()
        self.__ip_alloc = ipaddr.ipalloc(*subnet, is_ipv6=False)
        self.__timer = timer.timer()

    def get_ippkt2sLan_from_cLan(self, session_id, ippkt):
        clan_saddr = ippkt[12:16]
        slan_saddr = self.find_sLanAddr_by_cLanAddr(session_id, clan_saddr)

        if not slan_saddr:
            slan_saddr = self.__ip_alloc.get_addr()
            self.add2Lan(session_id, clan_saddr, slan_saddr)

        data_list = list(ippkt)
        checksum.modify_address(slan_saddr, data_list, checksum.FLAG_MODIFY_SRC_IP)
        self.__timer.set_timeout(slan_saddr, self.__VALID_TIME)

        return bytes(data_list)

    def get_ippkt2cLan_from_sLan(self, ippkt):
        slan_daddr = ippkt[16:20]
        rs = self.find_cLanAddr_by_sLanAddr(slan_daddr)

        if not rs: return None

        data_list = list(ippkt)
        checksum.modify_address(rs["clan_addr"], data_list, checksum.FLAG_MODIFY_DST_IP)
        self.__timer.set_timeout(slan_daddr, self.__VALID_TIME)

        return (rs["session_id"], bytes(data_list),)

    def recycle(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            self.delLan(name)
            self.__ip_alloc.put_addr(name)
        return


class nat6(_nat_base): pass
