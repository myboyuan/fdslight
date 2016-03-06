#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handler.handler as handler
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, os
import freenet.lib.fdsl_ctl as fdsl_ctl
import fdslight_etc.fn_client as fnc_config
import fdslight_etc.fn_server as fns_config
import freenet.lib.utils as utils
import freenet.lib.checksum as checksum


class traffic_read(handler.handler):
    """读取局域网的需要P2P的源数据包"""
    __creator_fd = -1

    def init_func(self, creator_fd, whitelist):
        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        subnet, mask = fnc_config.configs["udp_proxy_subnet"]
        n = utils.ip4s_2_number(subnet)

        fdsl_ctl.set_subnet(fileno, n, mask)

        self.set_fileno(fileno)
        self.__creator_fd = creator_fd

        for ip, mask in whitelist: fdsl_ctl.add_whitelist_subnet(fileno, ip, mask)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        if fnc_config.configs["global_udp"]:
            fdsl_ctl.udp_global(fileno)
        else:
            fdsl_ctl.udp_part(fileno)

        return self.fileno

    def evt_read(self):
        """最多读取10个数据包,防止陷入死循环"""
        for i in range(10):
            try:
                pkt = os.read(self.fileno, 8192)
            except BlockingIOError:
                break

            if not self.handler_exists(self.__creator_fd): return
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

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
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

    __raw_socket_fd = -1

    def init_func(self, creator_fd, raw_socket_fd):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.__creator_fd = creator_fd
        self.set_socket(s)
        self.bind(("0.0.0.0", 0))
        self.__bind_address = self.getsockname()
        self.__internet_ip = {}
        self.__raw_socket_fd = raw_socket_fd

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

        n_saddr = socket.inet_aton(saddr)
        n_daddr = socket.inet_aton(daddr)

        udp_packets = utils.build_udp_packet(n_saddr, n_daddr, sport, dport, message)

        for udp_pkt in udp_packets: self.send_message_to_handler(self.fileno, self.__creator_fd, udp_pkt)

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

    def message_from_handler(self, from_fd, byte_data):
        """接收到的数据是IP数据包"""
        version = (byte_data[0] & 0xf0) >> 4
        # 目前只支持IPv4
        if version != 4: return

        ihl = (byte_data[0] & 0x0f) * 4
        # pkt_id = (byte_data[4] << 8) | byte_data[5]
        flags = (byte_data[6] & 0xe0) >> 5
        # flag_df = (flags & 0x2) >> 1
        # flags_mf = flags & 0x1
        offset = ((byte_data[6] & 0x1f) << 5) | byte_data[7]

        bind_addr, bind_port = self.__bind_address
        bind_addr_pkt = socket.inet_aton(bind_addr)

        L = list(byte_data)

        if offset:
            self.__modify_src_address(bind_addr_pkt, L)
            message = bytes(L)
            self.send_message_to_handler(self.fileno, self.__raw_socket_fd, message)
            return

        src_addr = socket.inet_ntoa(byte_data[12:16])
        dst_addr = socket.inet_ntoa(byte_data[16:20])

        b = ihl
        e = ihl + 1
        sport = (byte_data[b] << 8) | byte_data[e]

        # 修改源端口
        e = e + 1
        L[b:e] = ((bind_port & 0xff00) >> 8, bind_port & 0x00ff,)

        #b = e + 1
        #e = b + 1
        #dport = (byte_data[b] << 8) | byte_data[e]

        b = ihl + 6
        e = b + 2

        # 改UDP校检和为0,即不计算校检和
        L[b:e] = (0, 0,)

        self.__modify_src_address(bind_addr_pkt, L)

        message = bytes(L)

        self.__lan_address = (src_addr, sport,)
        self.__internet_ip[dst_addr] = sport
        self.__timer.set_timeout(dst_addr, self.__UDP_SESSION_TIMEOUT)

        self.send_message_to_handler(self.fileno, self.__raw_socket_fd, message)

        return

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

        self.__udp_parser.recycle_resouce()
        return

    def udp_timeout(self):
        self.__clear_timeout_session()
        self.set_timeout(self.fileno, self.__TIMEOUT)
