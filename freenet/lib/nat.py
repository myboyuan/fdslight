#!/usr/bin/env python3
import freenet.lib.ipaddr as ipaddr
import freenet.lib.ipfrag as ipfrag
import pywind.lib.timer as timer
import socket, random
import freenet.lib.ippkts as ippkts
import freenet.lib.utils as utils


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

    def __init__(self, subnet):
        super(nat, self).__init__()
        self.__ip_alloc = ipaddr.ipalloc(*subnet, is_ipv6=False)
        self.__timer = timer.timer()

    def get_ippkt2sLan_from_cLan(self, session_id, mbuf):
        mbuf.offset = 12

        clan_saddr = mbuf.get_part(4)
        slan_saddr = self.find_sLanAddr_by_cLanAddr(session_id, clan_saddr)

        if not slan_saddr:
            try:
                slan_saddr = self.__ip_alloc.get_addr()
            except ipaddr.IpaddrNoEnoughErr:
                return False
            self.add2Lan(session_id, clan_saddr, slan_saddr)

        ippkts.modify_ip4address(slan_saddr, mbuf, flags=0)
        self.__timer.set_timeout(slan_saddr, self.__VALID_TIME)

        return True

    def get_ippkt2cLan_from_sLan(self, mbuf):
        mbuf.offset = 16

        slan_daddr = mbuf.get_part(4)
        rs = self.find_cLanAddr_by_sLanAddr(slan_daddr)

        if not rs: return False

        ippkts.modify_ip4address(rs["clan_addr"], mbuf, flags=1)
        self.__timer.set_timeout(slan_daddr, self.__VALID_TIME)

        return (True, rs["session_id"],)

    def recycle(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            self.delLan(name)
            self.__ip_alloc.put_addr(name)
        return


class nat66(object):
    """IPV6 NAT66实现,不支持数据分片
    """
    __byte_local_ip6 = None
    __timer = None

    __nat = None
    __nat_reverse = None

    # NAT超时时间
    __NAT_TIMEOUT = 900

    # ICMP超时时间
    __ICMP_TIMEOUT = 10

    __ip6_fragment = None

    def __init__(self, local_ip6):
        """
        :param local_ip6: 本机IPv6地址
        """
        self.__timer = timer.timer()
        self.__byte_local_ip6 = socket.inet_pton(socket.AF_INET6, local_ip6)
        self.__nat = {}
        self.__nat_reverse = {}
        self.__ip6_fragment = ipfrag.nat66()

    def __get_nat_id(self, mbuf, is_req=True):
        mbuf.offset = 8
        saddr = mbuf.get_part(16)

        mbuf.offset = 24
        daddr = mbuf.get_part(16)

        mbuf.offset = 6
        nexthdr = mbuf.get_part(1)

        mbuf.offset = 40

        if is_req:
            addr = saddr
        else:
            addr = daddr

        if nexthdr in (socket.IPPROTO_UDP, socket.IPPROTO_TCP):
            if not is_req: mbuf.offset += 2
            port = mbuf.get_part(2)
            return (
                b"".join((addr, chr(nexthdr).encode("iso-8859-1"), port,)),
                utils.bytes2number(port)
            )

        # ICMPV6
        mbuf.offset = 44
        icmp_id = mbuf.get_part(2)
        return (
            b"".join((addr, chr(nexthdr).encode("iso-8859-1"), icmp_id,)),
            utils.bytes2number(icmp_id)
        )

    def __is_support_nat(self, mbuf, is_req=True):
        """检查IP数据包是否支持NAT
        :param mbuf:
        :param is_req:是否是请求数据包
        :return:
        """
        mbuf.offset = 6
        nexthdr = mbuf.get_part(1)

        if nexthdr in ((6, 7, 17, 132, 136,)): return True
        if nexthdr != socket.IPPROTO_ICMPV6: return False

        # 检查ICMPv6类型是否支持NAT
        mbuf.offset = 40
        icmptype = mbuf.get_part(1)
        # 检查是否是echo请求
        if icmptype not in (128, 129): return False
        if icmptype == 128 and not is_req: return False
        if icmptype == 129 and is_req: return False

        return True

    def __get_nat_session(self, nexthdr, ushort):
        t = b"".join([
            self.__byte_local_ip6,
            chr(nexthdr).encode("iso-8859-1"),
            utils.number2bytes(ushort, 2)
        ])

        if t not in self.__nat_reverse: return ushort

        n_session_id = -1
        n = 0
        while n < 10:
            n_session_id = random.randint(1025, 65535)
            if n_session_id not in self.__nat_reverse: break
            n += 1

        return n_session_id

    def get_nat(self, session_id, mbuf):
        if not self.__is_support_nat(mbuf, is_req=True): return False

        if session_id not in self.__nat:
            self.__nat[session_id] = {}

        pydict = self.__nat[session_id]

        mbuf.offset = 8
        saddr = mbuf.get_part(16)

        mbuf.offset = 24
        daddr = mbuf.get_part(16)

        mbuf.offset = 6
        nexthdr = mbuf.get_part(1)

        # 对分包进行特殊处理
        if nexthdr == 44:
            ippkts.modify_ip6address_for_nat66(self.__byte_local_ip6, 0, mbuf, flags=0)
            return True

        nat_id, old_ushort = self.__get_nat_id(mbuf)

        if nat_id in pydict:
            ushort = pydict[nat_id]
        else:
            ushort = self.__get_nat_session(nexthdr, old_ushort)
            if ushort < 0: return False
            pydict[nat_id] = ushort

        t = b"".join([
            self.__byte_local_ip6,
            chr(nexthdr).encode("iso-8859-1"),
            utils.number2bytes(ushort, 2)
        ])

        if t not in self.__nat_reverse:
            self.__nat_reverse[t] = (session_id, nat_id, saddr, old_ushort, {daddr: None})
        else:
            self.__nat_reverse[t][4][daddr] = None

        ippkts.modify_ip6address_for_nat66(self.__byte_local_ip6, ushort, mbuf, flags=0)
        timeout = self.__NAT_TIMEOUT
        # 减少ICMP的超时时间
        if nexthdr == 58: timeout = self.__ICMP_TIMEOUT
        self.__timer.set_timeout(t, timeout)

        return True

    def get_nat_reverse(self, mbuf):
        if self.__is_support_nat(mbuf, is_req=False): return False
        mbuf.offset = 6
        nexthdr = mbuf.get_part(1)

        # 丢弃收到的分包
        if nexthdr == 44:
            return False

        nat_id, old_ushort = self.__get_nat_id(mbuf, is_req=False)
        if nat_id not in self.__nat_reverse: return

        session_id, nat_id, daddr, ushort, permits = self.__nat_reverse[nat_id]

        # 对接收的数据包进行地址限制,即地址限制型CONE NAT
        mbuf.offset = 8
        saddr = mbuf.get_part(16)
        if saddr not in permits: return False

        ippkts.modify_ip6address_for_nat66(daddr, ushort, mbuf, flags=1)

        timeout = self.__NAT_TIMEOUT
        # 减少ICMP的超时时间
        if nexthdr == 58: timeout = self.__ICMP_TIMEOUT
        self.__timer.set_timeout(nat_id, timeout)

        return True

    def __del_nat(self, nat_session_id):
        if nat_session_id not in self.__nat_reverse: return
        session_id, nat_id, _, _, _ = self.__nat_reverse[nat_session_id]
        pydict = self.__nat[session_id]

        del pydict[nat_id]
        if not pydict: del self.__nat[session_id]
        self.__timer.drop(nat_session_id)

    def recycle(self):
        for name in self.__timer.get_timeout_names():
            if not self.__timer.exists(name): continue
            self.__del_nat(name)
        return
