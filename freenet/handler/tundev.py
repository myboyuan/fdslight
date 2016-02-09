#!/usr/bin/env python3
import os, socket, sys

import freenet.handler.ipfwd as ipfwd
import pywind.evtframework.excepts as excepts


class tunc(ipfwd.tun_base):
    """客户端的tun数据处理
    """
    __dst_nat_table = {}
    __src_nat_table = {}

    # 分配到的虚拟IP列表
    __virtual_ips = None
    __TIMEOUT = 10

    def __get_new_src_ipaddr(self, packet_ip):
        """根据原来的ip获取freenet分配的IP地址
        :param src_ipaddr:
        :return:
        """
        if packet_ip not in self.__src_nat_table:
            try:
                new_packet_ip = self.__virtual_ips.pop(0)
            except IndexError:
                return None

            self.__src_nat_table[packet_ip] = new_packet_ip
            self.__dst_nat_table[new_packet_ip] = packet_ip
            return new_packet_ip

        return self.__src_nat_table[packet_ip]

    def __get_new_dst_ipaddr(self, packet_ip):
        """根据目的IP转换成用户自己的实际IP
        :param packet_ip:
        :return:
        """
        if packet_ip not in self.__dst_nat_table:
            return None

        return self.__dst_nat_table[packet_ip]

    def dev_init(self, dev_name):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__virtual_ips = []

        return

    def dev_error(self):
        print("client tun device error")
        sys.exit(-1)

    def dev_timeout(self):
        return

    def handle_ip_packet_for_write(self, ip_packet):
        L = list(ip_packet)
        dst_ip = ip_packet[16:20]

        new_dst_ip = self.__get_new_dst_ipaddr(dst_ip)

        if not new_dst_ip:
            return b""

        self.modify_address(new_dst_ip, L, modify_src_addr=False, fast_mode=True)

        return bytes(L)

    def handle_ip_packet_from_read(self, ip_packet):
        L = list(ip_packet)
        src_addr = ip_packet[12:16]

        new_src_ip = self.__get_new_src_ipaddr(src_addr)

        # IP地址不够直接丢弃数据包
        if not new_src_ip:
            return

        self.modify_address(new_src_ip, L, fast_mode=True)
        self.send_message_to_handler(self.fileno, self.creator_fd, bytes(L))

    def handler_ctl(self, from_fd, cmd, value):
        if from_fd != self.creator_fd:
            return False

        if cmd != "set_virtual_ips":
            return False

        self.__set_virtual_ips(value)

    def __set_virtual_ips(self, ips):
        for s in ips:
            packet_ip = socket.inet_aton(s)
            self.__virtual_ips.append(packet_ip)
        return

    def message_from_handler(self, from_fd, byte_data):
        dst_addr = byte_data[16:20]
        new_dst_ip = self.__get_new_dst_ipaddr(dst_addr)

        if not new_dst_ip:
            return

        self.add_evt_write(self.fileno)
        self.add_to_sent_queue(byte_data)


class tuns(ipfwd.tun_base):
    """服务端的tun数据处理
    """
    # 把目的IP与源IP进行关联
    __dst_ip_to_fd = None
    __TIMEOUT = 10

    def __add_route(self, dev_name, subnet):
        """给设备添加路由
        :param dev_name:
        :param subnet:
        :return:
        """
        ip, mask_size = subnet
        mask = 0

        for n in range(mask_size):
            mask |= 1 << (31 - n)

        t = socket.inet_aton(ip)
        i_ip = (t[0] << 24) | (t[1] << 16) | (t[2] << 8) | t[3]

        if i_ip & mask != (i_ip):
            print("error:netmask doesn't match route address")
            sys.exit(-1)

        cmd = "route add -net %s/%s dev %s" % (ip, mask_size, dev_name)
        os.system(cmd)

    def dev_init(self, tun_devname, subnet):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__dst_ip_to_fd = {}
        self.__add_route(tun_devname, subnet)

    def dev_error(self):
        print("error:server tun device error")
        self.delete_handler(self.fileno)

    def dev_timeout(self):
        pass

    def handle_ip_packet_from_read(self, ip_packet):
        dst_ip = ip_packet[16:20]

        from_fd = self.__dst_ip_to_fd.get(dst_ip, None)
        # 抛弃没有来源的IP数据包
        if not from_fd:
            return

        try:
            self.send_message_to_handler(self.fileno, from_fd, ip_packet)
        except excepts.HandlerNotFoundErr:
            return

    def handle_ip_packet_for_write(self, ip_packet):
        return ip_packet

    def dev_delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)
        sys.exit(-1)

    def message_from_handler(self, from_fd, ip_packet):
        src_ip = ip_packet[12:16]

        if from_fd not in self.__dst_ip_to_fd:
            self.__dst_ip_to_fd[src_ip] = from_fd

        self.add_evt_write(self.fileno)
        self.add_to_sent_queue(ip_packet)
