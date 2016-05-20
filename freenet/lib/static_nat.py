#!/usr/bin/env python3
import pywind.lib.timer as timer
import socket
import freenet.lib.checksum as checksum


class nat(object):
    """静态nat类"""
    # nat转换相关变量
    __dst_nat_table = None
    __src_nat_table = None
    # 分配到的虚拟IP列表
    __virtual_ips = None

    __timer = None
    # IP地址租赁有效期,如果超过这个时间,IP地址将被回收,以便可以让别的客户端可以连接
    __IP_TIMEOUT = 3600

    def __init__(self):
        self.__dst_nat_table = {}
        self.__src_nat_table = {}
        self.__virtual_ips = []
        self.__timer = timer.timer()

    def add_virtual_ips(self, ips):
        for ip in ips:
            ip_pkt = socket.inet_aton(ip)
            self.__virtual_ips.append(ip_pkt)
        return

    def get_new_packet_to_tunnel(self, pkt):
        """获取要发送到tunnel的IP包
        :param pkt:从局域网机器读取过来的包
        """
        src_addr = pkt[12:16]
        vir_ip = self.__src_nat_table.get(src_addr, None)

        if not vir_ip and not self.__virtual_ips: return None
        if not vir_ip: vir_ip = self.__virtual_ips.pop(0)

        pkt_list = list(pkt)
        checksum.modify_address(vir_ip, pkt_list, checksum.FLAG_MODIFY_SRC_IP)

        self.__timer.set_timeout(vir_ip, self.__IP_TIMEOUT)

        if vir_ip not in self.__dst_nat_table: self.__dst_nat_table[vir_ip] = src_addr
        if src_addr not in self.__src_nat_table: self.__src_nat_table[src_addr] = vir_ip

        return bytes(pkt_list)

    def get_new_packet_for_lan(self, pkt):
        """获取要发送给局域网机器的包
        :param pkt:收到的要发给局域网机器的包
        """
        dst_addr = pkt[16:20]
        # 如果没在nat表中,那么不执行转换
        if dst_addr not in self.__dst_nat_table: return None

        dst_lan = self.__dst_nat_table[dst_addr]
        self.__timer.set_timeout(dst_addr, self.__IP_TIMEOUT)
        pkt_list = list(pkt)
        checksum.modify_address(dst_lan, pkt_list, checksum.FLAG_MODIFY_DST_IP)

        return bytes(pkt_list)

    def recyle_ips(self):
        """回收已经分配出去的IP地址"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__dst_nat_table:
                t = self.__dst_nat_table[name]
                # 重新加入到待分配的列表中
                self.__virtual_ips.append(name)

                del self.__dst_nat_table[name]
                del self.__src_nat_table[t]
            if self.__timer.exists(name): self.__timer.drop(name)
        return

    def reset(self):
        self.__virtual_ips = []
        self.__dst_nat_table = {}
        self.__src_nat_table = {}
