#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handlers.handler as handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, os
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.checksum as checksum

class _qos(object):
    __queue = None

    def __init__(self):
        self.__queue = {}

    def add_data(self, ip_data):
        saddr = ip_data[12:16]
        if saddr not in self.__queue: self.__queue[saddr] = []
        self.__queue[saddr].append(ip_data)

    def get_data(self):
        results = []
        names = []

        for saddr in self.__queue:
            t = self.__queue[saddr]
            if t: results.append(t.pop(0))
            if not t: names.append(saddr)

        for saddr in names: del self.__queue[saddr]

        return results

    def has_data(self):
        return bool(self.__queue)


class traffic_read(handler.handler):
    """读取局域网的源数据包"""
    __tunnel_fd = -1
    __qos = None

    def init_func(self, creator_fd):
        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        self.__tunnel_fd = creator_fd
        self.__qos = _qos()

        self.set_fileno(fileno)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        sent_list = self.__qos.get_data()

        if not self.handler_exists(self.__tunnel_fd): return
        for ip_data in sent_list:
            self.send_message_to_handler(self.fileno, self.__tunnel_fd, ip_data)

        self.add_to_loop_task(self.fileno)
        """最多读取20个数据包,防止陷入死循环"""
        for i in range(20):
            try:
                pkt = os.read(self.fileno, 8192)
            except BlockingIOError:
                break
            if not pkt: continue
            self.__qos.add_data(pkt)
        return

    def delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)

    def task_loop(self):
        if not self.__qos.has_data():
            self.del_loop_task(self.fileno)
            return
        self.evt_read()


class traffic_send(handler.handler):
    """把数据包发送到局域网的设备"""
    __creator_fd = -1
    __sent = None
    __socket = None

    def init_func(self, creator_fd, is_ipv6=False):
        self.__creator_fd = creator_fd
        self.__sent = []

        family = socket.AF_INET
        if is_ipv6: family = socket.AF_INET6

        s = socket.socket(family, socket.SOCK_RAW,
                          socket.IPPROTO_UDP | socket.IPPROTO_ICMP | socket.IPPROTO_UDP)
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
            try:
                sent_len = self.__socket.sendto(ippkt, (dst_addr, 0))
            except BlockingIOError:
                self.__sent.insert(0, ippkt)
                return

            if pkt_len > sent_len:
                self.__sent.insert(0, ippkt)
                break
            ''''''
        return

    def message_from_handler(self, from_fd, byte_data):
        self.add_evt_write(self.fileno)
        self.__sent.append(byte_data)

    def delete(self):
        self.unregister(self.fileno)
        self.__socket.close()


class udp_proxy(udp_handler.udp_handler):
    __bind_address = None
    __internet_ip = None

    # UDP会话超时时间,如果超过这个时间,将从认证会话中删除
    __UDP_SESSION_TIMEOUT = 300
    # handler超时时间
    __LOOP_TIMEOUT = 10

    __timer = None

    # id号,用以对数据包进行区分
    __uniq_id = None

    __raw_socket_fd = -1
    __is_ipv6 = False

    __ipaddr = None
    __port = None

    def init_func(self, creator_fd, raw_socket_fd, uniq_id, ipaddr, port, is_ipv6=False):
        family = socket.AF_INET
        if is_ipv6: family = socket.AF_INET6

        s = socket.socket(family, socket.SOCK_DGRAM)

        self.set_socket(s)

        if is_ipv6:
            self.bind(("::", 0))
        else:
            self.bind(("0.0.0.0", 0))

        self.__bind_address = self.getsockname()
        self.__internet_ip = {}
        self.__raw_socket_fd = raw_socket_fd

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__timer = timer.timer()
        self.__uniq_id = uniq_id
        self.__is_ipv6 = is_ipv6
        self.__ipaddr = ipaddr
        self.__port = port

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        saddr, sport = address

        # 检查源IP是否合法,如果客户机没有发送过,那么丢弃这个UDP包
        if saddr not in self.__internet_ip: return

        if self.__is_ipv6:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET

        n_saddr = socket.inet_pton(family, saddr)
        n_daddr = socket.inet_pton(family, self.__ipaddr)

        # 预留IPv6接口
        if self.__is_ipv6:
            return
        else:
            udp_packets = utils.build_udp_packets(n_saddr, n_daddr, sport, self.__port, message)
        for udp_pkt in udp_packets:
            self.dispatcher.send_msg_to_handler_from_udp_proxy(
                self.__uniq_id, udp_pkt
            )
        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def __modify_src_address(self, new_ip_pkt, pkt_list):
        """修改源地址"""
        old_checsum = (pkt_list[10] << 8) | pkt_list[11]
        new_csum = checksum.calc_checksum_for_ip_change(
            bytes(pkt_list[12:16]), new_ip_pkt, old_checsum
        )

        pkt_list[10:12] = ((new_csum & 0xff00) >> 8, new_csum & 0x00ff,)
        pkt_list[12:16] = new_ip_pkt

    def __handle_ipv4_data_for_send(self, byte_data):
        ihl = (byte_data[0] & 0x0f) * 4
        bind_addr, bind_port = self.__bind_address
        bind_addr_pkt = socket.inet_aton(bind_addr)
        L = list(byte_data)

        dst_addr = socket.inet_ntoa(byte_data[16:20])

        b = ihl
        e = ihl + 1
        sport = (byte_data[b] << 8) | byte_data[e]
        # 修改源端口
        e = e + 1
        L[b:e] = ((bind_port & 0xff00) >> 8, bind_port & 0x00ff,)

        b = ihl + 6
        e = b + 2

        # 改UDP校检和为0,即不计算校检和
        L[b:e] = (0, 0,)

        self.__modify_src_address(bind_addr_pkt, L)

        message = bytes(L)
        self.__internet_ip[dst_addr] = sport
        self.__timer.set_timeout(dst_addr, self.__UDP_SESSION_TIMEOUT)
        self.send_message_to_handler(self.fileno, self.__raw_socket_fd, message)
        return

    def __handle_ipv6_data_for_send(self, byte_data):
        pass

    def message_from_handler(self, from_fd, byte_data):
        """接收到的数据是IP数据包"""
        version = (byte_data[0] & 0xf0) >> 4
        if version not in (4, 6,): return
        if version == 4 and self.__is_ipv6: return
        if version == 6 and not self.__is_ipv6: return
        if version == 4: self.__handle_ipv4_data_for_send(byte_data)
        if version == 6: self.__handle_ipv6_data_for_send(byte_data)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.del_udp_proxy(self.__uniq_id, self.__ipaddr, self.__port)
        self.unregister(self.fileno)
        self.socket.close()

    def __clear_timeout_session(self):
        """删除超时的会话"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__internet_ip: del self.__internet_ip[name]
            if self.__timer.exists(name): self.__timer.drop(name)
        return

    def udp_timeout(self):
        self.__clear_timeout_session()
        if self.__internet_ip:
            self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
            return
        self.delete_handler(self.fileno)

