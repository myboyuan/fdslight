#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handler.handler as handler
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, os
import freenet.lib.fdsl_ctl as fdsl_ctl
import fdslight_etc.fn_client as fn_config
import freenet.lib.utils as utils


class traffic_read(handler.handler):
    """读取局域网的需要P2P的源数据包"""
    __creator_fd = -1

    def init_func(self, creator_fd, whitelist):
        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        subnet, mask = fn_config.configs["proxy_subnet"]
        n = utils.ip4s_2_number(subnet)

        fdsl_ctl.set_subnet(fileno, n, mask)

        self.set_fileno(fileno)
        self.__creator_fd = creator_fd

        for ip, mask in whitelist: fdsl_ctl.add_whitelist_subnet(fileno, ip, mask)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        """最多读取10个数据包,防止陷入死循环"""
        for i in range(10):
            try:
                pkt = os.read(self.fileno, 8192)
            except BlockingIOError:
                break
            self.send_message_to_handler(self.fileno, self.__creator_fd, pkt)
        return

    def delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)


class traffic_send(handler.handler):
    """把数据包发送到局域网的设备"""
    __creator_fd = -1
    __sent = None
    __socket = None

    def init_func(self, creator_fd):
        self.__creator_fd = creator_fd
        self.__sent = []

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(0)

        self.__socket = s
        self.set_fileno(s.fileno())
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        """丢弃所有收到的包"""
        while 1:
            try:
                _ = self.__socket.recvfrom(8192)
            except BlockingIOError:
                break
            ''''''
        return

    def evt_write(self):
        if not self.__sent: self.remove_evt_write(self.fileno)

        while 1:
            try:
                ippkt = self.__sent.pop(0)
            except IndexError:
                break

            ip_ver = (ippkt[0] & 0xf0) >> 4

            # 目前只支持IPv4
            if ip_ver != 4: continue

            dst_addr_pkt = ippkt[16:20]
            dst_addr = socket.inet_ntoa(dst_addr_pkt)
            pkt_len = (ippkt[2] << 8) | ippkt[3]
            sent_len = self.__socket.sendto(ippkt, (dst_addr, 0))

            if pkt_len > sent_len:
                self.__sent.index(0, ippkt)
                break
            ''''''
        return

    def message_from_handler(self, from_fd, byte_data):
        if from_fd != self.__creator_fd: return

        self.add_evt_write(self.fileno)
        self.__sent.append(byte_data)

    def delete(self):
        self.unregister(self.fileno)
        self.__socket.close()


class handler_manager(object):
    """管理nat handler
    """
    __map = None

    def __init__(self):
        self.__map = {}

    def __build_key(self, ip, port):
        return "%s-%s" % (ip, port)

    def add(self, ip, port, fileno):
        name = self.__build_key(ip, port)
        self.__map[name] = fileno

    def exists(self, ip, port):
        name = self.__build_key(ip, port)
        return name in self.__map

    def delete(self, ip, port):
        name = self.__build_key(ip, port)
        if name not in self.__map: return
        del self.__map[name]

    def get(self, ip, port):
        name = self.__build_key(ip, port)
        return self.__map[name]

    def get_all_fileno(self):
        vals = []
        for key in self.__map: vals.append(self.__map[key])
        return vals


class udp_proxy(udp_handler.udp_handler):
    __creator_fd = -1
    __bind_address = None

    __lan_address = None
    __internet_ip = None

    # UDP会话超时时间,如果超过这个时间,将从认证会话中删除
    __UDP_SESSION_TIMEOUT = 3 * 60
    # handler超时时间
    __TIMEOUT = 4 * 60

    __timer = None

    def init_func(self, creator_fd):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.__creator_fd = creator_fd
        self.set_socket(s)
        self.bind(("0.0.0.0", 0))
        self.__bind_address = self.getsockname()
        self.__internet_ip = {}

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__TIMEOUT)
        self.__timer = timer.timer()

        return self.fileno

    def udp_readable(self, message, address):
        if not self.__lan_address: return
        saddr, sport = address

        # 检查源IP是否合法,如果客户机没有发送过,那么丢弃这个UDP包
        if saddr not in self.__internet_ip: return

        self.set_timeout(self.fileno, self.__TIMEOUT)
        daddr, dport = self.__lan_address

        udp_packet = utils.build_udp_packet(saddr, daddr, sport, dport, message)

        self.send_message_to_handler(self.fileno, self.__creator_fd, udp_packet)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def message_from_handler(self, from_fd, byte_data):
        """接收到的数据是IP数据包"""
        version = (byte_data[0] & 0xf0) >> 4
        # 目前只支持IPv4
        if version != 4: return

        ihl = (byte_data[0] & 0x0f) * 4

        src_addr = socket.inet_ntop(socket.AF_INET, byte_data[12:16])
        dst_addr = socket.inet_ntop(socket.AF_INET, byte_data[16:20])

        if b"\0\0\0\0" == dst_addr: return

        udp_data = byte_data[ihl:]

        sport = (udp_data[0] << 8) | udp_data[1]
        dport = (udp_data[2] << 8) | udp_data[3]

        self.__lan_address = (src_addr, sport)
        self.__internet_ip[dst_addr] = sport
        self.__timer.set_timeout(dst_addr, self.__UDP_SESSION_TIMEOUT)

        app_data = udp_data[8:]

        self.set_timeout(self.fileno, self.__TIMEOUT)
        self.add_evt_write(self.fileno)

        # 目标端口为0 Linux会报错，暂时没想到办法,而Windows可以
        if dport == 0: return
        self.sendto(app_data, (dst_addr, dport))

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

    def __clear_timeout_session(self):
        """删除超时的会话"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__internet_ip: del self.__internet_ip[name]
            self.__timer.drop(name)
        return

    def udp_timeout(self):
        self.__clear_timeout_session()
        self.set_timeout(self.fileno, self.__TIMEOUT)
