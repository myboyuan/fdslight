#!/usr/bin/env python3
"""
实现ip数据包的转发
"""
import os, sys, socket
import pywind.evtframework.handler.handler as handler
import freenet.lib.fn_utils as fn_utils
import freenet.lib.checksum as checksum

try:
    import fcntl
except ImportError:
    pass


class tun_base(handler.handler):
    __creator_fd = None
    # tun设备名前缀
    __ip_alloc = None
    # 要写入到tun的IP包
    ___ip_packets_for_write = []
    # 写入tun设备的最大IP数据包的个数
    __MAX_WRITE_QUEUE_SIZE = 20
    # 当前需要写入tun设备的IP数据包的个数
    __current_write_queue_n = 0

    def __calc_checksum_for_ip_change(self, old_ip_packet, new_ip_packet, old_checksum):
        """ ip地址改变之后重新获取校检码
        :param old_ip_packet:
        :param new_ip_packet:
        :param old_checksum:
        :return:
        """
        final_checksum = old_checksum
        a = 0
        b = 1
        #tmpcsum = old_checksum

        for i in range(2):
            old_field = (old_ip_packet[a] << 8) | old_ip_packet[b]
            new_field = (new_ip_packet[a] << 8) | new_ip_packet[b]
            # final_checksum = checksum.calc_incre_checksum(final_checksum, old_field, new_field)
            final_checksum = fn_utils.calc_incre_csum(final_checksum, old_field, new_field)
            a = a + 2
            b = b + 2

        return final_checksum

    def __modify_ip_packet_hdr(self, ip_packet, ip_packet_list, flags=0):
        """修改IP包头
        :param ip_packet: 新的bytes类型的IP地址
        :param ip_packet_list: list类型的IP包
        :param flags: 0表示修改的是源地址,1表示修改的是目的地址
        :return:
        """
        if flags:
            a = 16
            b = 20
        else:
            a = 12
            b = 16

        old_checksum = (ip_packet_list[10] << 8) | ip_packet_list[11]

        old_ip_packet = ip_packet_list[a:b]
        checksum = self.__calc_checksum_for_ip_change(old_ip_packet, ip_packet, old_checksum)

        ip_packet_list[10:12] = [
            (checksum & 0xff00) >> 8,
            checksum & 0x00ff
        ]

        if flags:
            ip_packet_list[16:20] = ip_packet
        else:
            ip_packet_list[12:16] = ip_packet
        return

    def __modify_tcp_and_udp_checksum_for_ip_change(self, ip_packet, ip_packet_list, proto, flags=0):
        """ IP改变的时候重新计算TCP和UDP的校检和
        :param ip_packet:
        :param ip_packet_list:
        :param proto: 0表示计算的UDP,1表示计算的TCP
        :param flags: 0 表示修改时的源地址,1表示修改的是目的地址
        :return:
        """
        if proto not in [0, 1]:
            return

        hdr_len = (ip_packet_list[0] & 0x0f) * 4

        if flags:
            a = 16
            b = 20
        else:
            a = 12
            b = 16

        old_ip_packet = ip_packet_list[a:b]
        if proto == 0:
            a = hdr_len + 6
        if proto == 1:
            a = hdr_len + 16

        b = a + 1
        old_checksum = (ip_packet_list[a] << 8) | ip_packet_list[b]
        # 如果旧的校检和为0,说明不需要进行校检和计算
        if old_checksum == 0:
            return
        checksum = self.__calc_checksum_for_ip_change(old_ip_packet, ip_packet, old_checksum)

        ip_packet_list[a] = (checksum & 0xff00) >> 8
        ip_packet_list[b] = checksum & 0x00ff

    def __create_tun_dev(self, name):
        """创建tun 设备
        :param name:
        :return fd:
        """
        tun_fd = fn_utils.tuntap_create(name, fn_utils.IFF_TUN | fn_utils.IFF_NO_PI)
        fn_utils.interface_up(name)

        if tun_fd < 0:
            raise SystemError("can not create tun device,please check your root")

        return tun_fd

    def init_func(self, creator_fd, tun_dev_name, *args, **kwargs):
        """
        :param creator_fd:
        :param tun_dev_name:tun 设备名称
        :param subnet:如果是服务端则需要则个参数
        """
        tun_fd = self.__create_tun_dev(tun_dev_name)

        if tun_fd < 3:
            print("error:create tun device failed:%s" % tun_dev_name)
            sys.exit(-1)

        self.__creator_fd = creator_fd

        self.set_fileno(tun_fd)
        fcntl.fcntl(tun_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        self.dev_init(tun_dev_name, *args, **kwargs)

        return tun_fd

    def dev_init(self, dev_name, *args, **kwargs):
        pass

    def evt_read(self):
        try:
            ip_packet = os.read(self.fileno, 2048)
        except BlockingIOError:
            return

        self.handle_ip_packet_from_read(ip_packet)

    def evt_write(self):
        try:
            ip_packet = self.___ip_packets_for_write.pop(0)
        except IndexError:
            self.remove_evt_write(self.fileno)
            return

        self.__current_write_queue_n -= 1
        ip_version = (ip_packet[0] & 0xf0) >> 4
        # 放弃处理IP版本不是4的数据包
        if ip_version != 4:
            return

        try:
            os.write(self.fileno, ip_packet)
        except BlockingIOError:
            self.__current_write_queue_n += 1
            self.___ip_packets_for_write.insert(0, ip_packet)
            return
        ''''''

    def handle_ip_packet_from_read(self, ip_packet):
        """处理读取过来的IP包,重写这个方法
        :param ip_packet:
        :return None:
        """
        pass

    def handle_ip_packet_for_write(self, ip_packet):
        """处理要写入的IP包,重写这个方法
        :param ip_packet:
        :return new_ip_packet:
        """
        pass

    def error(self):
        self.dev_error()

    def dev_error(self):
        """重写这个方法
        :return:
        """
        pass

    def timeout(self):
        self.dev_timeout()

    def dev_timeout(self):
        """重写这个方法
        :return:
        """
        pass

    def delete(self):
        self.dev_delete()

    def dev_delete(self):
        """重写这个方法
        :return:
        """
        pass

    def modify_address(self, ip, ip_packet_list, modify_src_addr=True, fast_mode=False):
        """修改地址
        :param new_ip:
        :param ip_packet_list:list数据结构的IP包
        :param modify_src_addr: True表示修改源地址,否则修改目的地址
        :param fast_mode:快速模式,如果是快速模式,那么参数ip是bytes类型,否则是ip字符串类型
        :return:
        """
        if fast_mode:
            new_ip = ip
        else:
            new_ip = socket.inet_pton(socket.AF_INET, ip)

        if modify_src_addr:
            flags = 0
        else:
            flags = 1

        protocol = ip_packet_list[9]
        # TCP
        if protocol == 6:
            self.__modify_tcp_and_udp_checksum_for_ip_change(new_ip, ip_packet_list, 1, flags)
        # UDP
        if protocol == 17:
            self.__modify_tcp_and_udp_checksum_for_ip_change(new_ip, ip_packet_list, 0, flags)

        self.__modify_ip_packet_hdr(new_ip, ip_packet_list, flags)

    def add_to_sent_queue(self, ip_packet):
        # 丢到超出规定的数据包,防止内存过度消耗
        if self.__current_write_queue_n == self.__MAX_WRITE_QUEUE_SIZE:
            return

        self.__current_write_queue_n += 1
        n_ip_message = self.handle_ip_packet_for_write(ip_packet)

        if not n_ip_message:
            return

        self.___ip_packets_for_write.append(n_ip_message)

    @property
    def creator_fd(self):
        return self.__creator_fd

    def clear_resource(self):
        pass
