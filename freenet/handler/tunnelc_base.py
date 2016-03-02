#!/usr/bin/env python3
"""
隧道客户端基本类
"""
import json, socket, sys, time

import fdslight_etc.fn_client as fnc_config
import freenet.lib.base_proto.over_tcp as over_tcp
import pywind.evtframework.handler.tcp_handler as tcp_handler
import pywind.lib.timer as timer
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.checksum as checksum
import freenet.lib.ipfragment as ipfragment


class _static_nat(object):
    """静态nat类"""
    # nat转换相关变量
    __dst_nat_table = None
    __src_nat_table = None
    # 分配到的虚拟IP列表
    __virtual_ips = None

    __timer = None
    # IP地址租赁有效期,如果超过这个时间,IP地址将被回收,以便可以让别的客户端可以连接
    __IP_TIMEOUT = 240

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
        self.__dst_nat_table[vir_ip] = src_addr
        self.__src_nat_table[src_addr] = vir_ip

        return bytes(pkt_list)

    def get_new_packet_for_lan(self, pkt):
        """获取要发送给局域网机器的包
        :param pkt:收到的要发给局域网机器的包
        """
        dst_addr = pkt[16:20]
        # 如果没在nat表中,那么不执行转换
        if dst_addr not in self.__dst_nat_table: return None

        dst_lan = self.__dst_nat_table[dst_addr]
        self.__timer.set_timeout(dst_lan, self.__IP_TIMEOUT)
        pkt_list = list(pkt)
        checksum.modify_address(dst_lan, pkt_list, checksum.FLAG_MODIFY_DST_IP)

        return bytes(pkt_list)

    def recyle_ips(self):
        """回收已经分配出去的IP地址"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__src_nat_table:
                t = self.__src_nat_table[name]
                # 重新加入到待分配的列表中
                self.__virtual_ips.append(name)

                del self.__dst_nat_table[t]
                del self.__src_nat_table[name]
            self.__timer.drop(name)
        return


class tcp_tunnelc_base(tcp_handler.tcp_handler):
    __encrypt_m = None
    __decrypt_m = None
    __TIMEOUT = 1 * 60
    # 是否已经发送过验证报文
    __is_sent_auth = False

    __timer = None
    __static_nat = None

    # 最大缓冲区大小
    __MAX_BUFFER_SIZE = 16 * 1024

    __traffic_catch_fd = -1
    __traffic_send_fd = -1

    __tun_fd = -1
    __dns_fd = -1

    __udp_fragment = None

    def init_func(self, creator_fd, whitelist):
        server_addr = fnc_config.configs["tcp_server_address"]

        s = socket.socket()

        try:
            s.connect(server_addr)
        except:
            self.print_access_log("connect_failed")
            return

        self.set_socket(s)
        name = "freenet.lib.crypto.%s" % fnc_config.configs["tcp_crypto_module"]
        __import__(name)
        m = sys.modules[name]

        self.__encrypt_m = m.encrypt()
        self.__decrypt_m = m.decrypt()

        self.__static_nat = _static_nat()

        self.__traffic_catch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read, whitelist)
        self.__traffic_send_fd = self.create_handler(self.fileno, traffic_pass.traffic_send)
        self.__udp_fragment = ipfragment.udp_fragment()

        return self.fileno

    def after(self, tun_fd, dns_fileno):
        self.__tun_fd = tun_fd
        self.__dns_fd = dns_fileno

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.add_evt_write(self.fileno)

    def __send_pong(self):
        """发送pong帧
        :return:
        """
        pong = self.encrypt_m.build_pong()
        self.add_evt_write(self.fileno)
        self.writer.write(pong)

    def __send_close(self):
        """发送close帧
        :return:
        """
        close = self.encrypt_m.build_close()
        self.add_evt_write(self.fileno)
        self.writer.write(close)

    def __send_auth(self, pydict):
        self.__is_sent_auth = True
        sts = json.dumps(pydict)
        data_size = len(sts)
        self.encrypt_m.set_body_size(data_size)
        hdr = self.encrypt_m.wrap_header(over_tcp.ACT_AUTH)
        body = self.encrypt_m.wrap_body(sts.encode("utf-8"))

        self.writer.write(hdr)
        self.writer.write(body)

        self.encrypt_m.reset()
        return

    def __handle_read_data(self, action, byte_data):
        if action not in over_tcp.ACTS: return
        if over_tcp.ACT_AUTH == action:
            ret = self.fn_auth_response(byte_data)
            if not ret:
                self.print_access_log("auth_failed")
                self.delete_handler(self.fileno)
            else:
                self.print_access_log("auth_ok")
            return
        if over_tcp.ACT_CLOSE == action:
            print("connection_close")
            self.delete_handler(self.fileno)
            return
        if over_tcp.ACT_PONG == action: return
        if over_tcp.ACT_PING == action:
            self.__send_pong()
            return
        new_pkt = self.__static_nat.get_new_packet_for_lan(byte_data)
        if not new_pkt: return
        proto = new_pkt[9]

        if 17 == proto:
            t_fd = self.__traffic_send_fd
        else:
            t_fd = self.__tun_fd

        self.send_message_to_handler(self.fileno, t_fd, new_pkt)

    def tcp_readable(self):
        self.set_timeout(self.fileno, self.__TIMEOUT)
        rdata = self.reader.read()
        self.__decrypt_m.add_data(rdata)

        while self.__decrypt_m.have_data():
            if not self.__decrypt_m.is_ok(): return
            action = self.__decrypt_m.header_info()
            body_data = self.__decrypt_m.body_data()
            self.__decrypt_m.reset()
            self.__handle_read_data(action, body_data)

        return

    def tcp_writable(self):
        if not self.__is_sent_auth:
            ret_data = self.fn_auth_request()
            self.__send_auth(ret_data)
            return
        if self.writer.size() < 1:
            self.remove_evt_write(self.fileno)
            return
        self.set_timeout(self.fileno, self.__TIMEOUT)
        return

    def __send_to_tunnel(self, packet_length, byte_data, action=over_tcp.ACT_DATA):
        """向加密发送数据"""
        self.encrypt_m.set_body_size(packet_length)
        hdr = self.encrypt_m.wrap_header(action)
        body = self.encrypt_m.wrap_body(byte_data)

        self.encrypt_m.reset()
        self.add_evt_write(self.fileno)
        self.writer.write(hdr)
        self.writer.write(body)

    def message_from_handler(self, from_fd, byte_data):
        if from_fd == self.__dns_fd:
            self.__send_to_tunnel(len(byte_data), byte_data, action=over_tcp.ACT_DNS)
            return
        # 没发送验证数据包就丢弃网卡的数据包
        if not self.__is_sent_auth: return
        # 防止内存过度消耗
        if self.writer.size() > self.__MAX_BUFFER_SIZE: return
        # 目前只支持IPv4
        if (byte_data[0] & 0xf0) >> 4 != 4: return
        new_pkt = self.__static_nat.get_new_packet_to_tunnel(byte_data)
        if not new_pkt: return

        packet_length = (new_pkt[2] << 8) | new_pkt[3]
        protocol = new_pkt[9]

        if protocol != 17:
            self.__send_to_tunnel(packet_length, new_pkt)
            return

        flags = (new_pkt[6] & 0xe0) >> 5
        flags_df = (flags & 0x2) >> 1

        # 不能分段的数据包直接发送
        if flags_df:
            self.__send_to_tunnel(packet_length, new_pkt)
            return

        # 进行分片组包
        self.__udp_fragment.add_data(new_pkt)
        while 1:
            udp_pkt = self.__udp_fragment.get_packet()
            if not udp_pkt: break
            pkt_len = (udp_pkt[2] << 8) | udp_pkt[3]
            self.__send_to_tunnel(pkt_len, udp_pkt)
        return

    def tcp_error(self):
        if not self.__is_sent_auth:
            self.print_access_log("auth_timeout")
        else:
            self.print_access_log("server_closed")

        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

        self.delete_handler(self.__traffic_catch_fd)
        self.delete_handler(self.__traffic_send_fd)

        self.print_access_log("re_connect")
        self.dispatcher.client_need_reconnect()

    def tcp_timeout(self):
        # 回收IP资源,以便别的机器能够顺利连接
        self.__static_nat.recyle_ips()
        # 回收一些只发送了部分的IP分包的数据包的内存
        self.__udp_fragment.recycle_resouce()

    def print_access_log(self, string):
        t = time.strftime("time:%Y-%m-%d %H:%M:%S")
        ipaddr = "%s:%s" % fnc_config.configs["tcp_server_address"]

        text = "%s      %s      %s" % (string, ipaddr, t)
        print(text)

    @property
    def encrypt_m(self):
        return self.__encrypt_m

    @property
    def decrypt_m(self):
        return self.__decrypt_m

    def fn_auth_request(self):
        """
        :return dict:返回一个字典对象
        """
        pass

    def fn_auth_response(self, auth_resp_info):
        """验证响应之后调用该函数
        :param auth_resp_info:
        :return Boolean: True表示系统继续执行,False则表示停止执行
        """
        return True

    def set_virtual_ips(self, ips):
        """设置虚拟IP"""
        self.__static_nat.add_virtual_ips(ips)
