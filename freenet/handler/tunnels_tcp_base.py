#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import socket, time, sys
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.checksum as checksum
import freenet.lib.ipaddr as ipaddr


class _tunnel_tcp_listen(tcp_handler.tcp_handler):
    __debug = None
    __module = None
    __tun_fd = -1
    __dns_fd = None

    __support_protos = (
        socket.IPPROTO_UDP, socket.IPPROTO_TCP, socket.IPPROTO_ICMP, 132,
    )
    __dns_fd = None
    __ip_pool = None

    # 最大连接数
    __max_conns = 10
    # 当前连接数
    __curr_conns = 0

    __raw_socket_fd = -1

    def init_func(self, creator_fd, tun_fd, dns_fd, raw_socket_fd, ip_pool, debug=True):
        self.__debug = debug
        self.__max_conns = fns_config.configs["max_tcp_conns"]

        name = "freenet.tunnels.%s" % fns_config.configs["tcp_tunnel"]
        __import__(name)
        self.__module = sys.modules[name]
        self.__ip_pool = ip_pool

        self.__tun_fd = tun_fd
        self.__dns_fd = dns_fd
        self.__raw_socket_fd = raw_socket_fd

        s = socket.socket()
        self.set_socket(s)
        self.bind(fns_config.configs["tcp_listen"])

        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            if self.__curr_conns == self.__max_conns:
                cs.close()
                return
            self.__curr_conns += 1
            self.create_handler(self.fileno, self.__module.tunnel, self.__raw_socket_fd,
                                self.__tun_fd,
                                cs, caddr,
                                debug=self.__debug
                                )
            ''''''
        return

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def __get_vlan_ips(self, n):
        results = []
        for i in range(n):
            try:
                ippkt = self.__ip_pool.get_addr()
            except ipaddr.IpaddrNoEnoughErr:
                # 回收IP地址
                for ip in results:
                    self.__ip_pool.put_addr(ip)
                results = []
                break
            results.append(ippkt)
        return results

    def __put_vlan_ips(self, ips):
        for ip in ips: self.__ip_pool.put_addr(ip)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("request_dns", "response_dns", "del_conn", "get_vlan_ips", "put_vlan_ips",): return None
        if cmd == "del_conn": self.__curr_conns -= 1
        if cmd == "request_dns":
            dns_msg, = args
            self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", from_fd, dns_msg)
        if cmd == "response_dns":
            t_fd, resp_dns_msg, = args
            if not self.handler_exists(t_fd): return None
            self.ctl_handler(self.fileno, t_fd, "response_dns", resp_dns_msg)
        if cmd == "get_vlan_ips":
            n, = args
            return self.__get_vlan_ips(n)
        if cmd == "put_vlan_ips":
            ips, = args
            self.__put_vlan_ips(ips)
            return

        return None


class tunnels_tcp_base(tcp_handler.tcp_handler):
    __debug = None
    __caddr = None
    __TIMEOUT_NO_AUTH = 10
    __TIMEOUT = 480

    __encrypt = None
    __decrypt = None
    __auth_ok = False

    __creator_fd = None
    __is_sent_ping = False

    # ip,port到文件描述符的映射
    __udp_natp_to_fd = None
    __vlan_ips = None
    __traffic_send_fd = -1
    __tun_fd = -1
    __udp_proxy_map = None

    def __get_id(self, address):
        """根据地址生成唯一id"""
        return "%s-%s" % address

    def __udp_local_proxy_for_send(self, byte_data):
        """当地UDP代理,该代理不经过加密隧道"""
        ihl = (byte_data[0] & 0x0f) * 4
        offset = ((byte_data[6] & 0x1f) << 5) | byte_data[7]

        # 说明不是第一个数据分包,那么就直接发送给raw socket
        if offset:
            L = list(byte_data)
            checksum.modify_address(b"\0\0\0\0", L, checksum.FLAG_MODIFY_SRC_IP)
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, bytes(L))
            return

        b, e = (ihl, ihl + 1,)
        sport = (byte_data[b] << 8) | byte_data[e]
        saddr = socket.inet_ntoa(byte_data[12:16])
        uniq_id = self.__get_id((saddr, sport,))

        fileno = 0
        if uniq_id not in self.__udp_natp_to_fd:
            fileno = self.create_handler(self.fileno, traffic_pass.udp_proxy,
                                         self.__traffic_send_fd, (saddr, sport,),
                                         uniq_id)
            self.__udp_natp_to_fd[uniq_id] = fileno
        else:
            fileno = self.__udp_natp_to_fd[uniq_id]
        self.send_message_to_handler(self.fileno, fileno, byte_data)

    def init_func(self, creator_fd, raw_socket_fd, tun_fd, cs, caddr, debug=True):
        self.__debug = debug
        self.__caddr = caddr

        name = "freenet.lib.crypto.%s" % fns_config.configs["tcp_crypto_module"]["name"]
        __import__(name)

        crypto = sys.modules[name]

        args = fns_config.configs["tcp_crypto_module"]["args"]

        self.__encrypt = crypto.encrypt(*args)
        self.__decrypt = crypto.decrypt(*args)
        self.__creator_fd = creator_fd
        self.__traffic_send_fd = raw_socket_fd
        self.__vlan_ips = []
        self.__udp_natp_to_fd = {}
        self.__tun_fd = tun_fd

        self.set_socket(cs)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__TIMEOUT_NO_AUTH)
        self.print_access_log("connect")

        return self.fileno

    def __send_data(self, pkt_len, byte_data, action=tunnel_tcp.ACT_DATA):
        if action == tunnel_tcp.ACT_DATA:
            if not self.fn_send(pkt_len):
                self.delete_handler(self.fileno)
                return
            ''''''
        sent_data = self.encrypt.build_packet(action, pkt_len, byte_data)
        self.writer.write(sent_data)
        self.add_evt_write(self.fileno)
        self.encrypt.reset()

    def send_auth(self, byte_data):
        size = len(byte_data)
        self.__send_data(size, byte_data, action=tunnel_tcp.ACT_AUTH)

    def __send_ping(self):
        if self.__debug: self.print_access_log("send_ping")
        self.__send_data(0, b"", action=tunnel_tcp.ACT_PING)
        self.__is_sent_ping = True

    def __send_pong(self):
        if self.__debug: self.print_access_log("send_pong")
        self.__send_data(0, b"", action=tunnel_tcp.ACT_PONG)

    def __handle_data(self, byte_data):
        # 限制只支持IPv4
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver != 4: return
        pkt_len = (byte_data[2] << 8) | byte_data[3]
        if len(byte_data) != pkt_len:
            self.print_access_log("error_pkt_length:real:%s,protocol:%s" % (len(byte_data), pkt_len,))
            self.delete_handler(self.fileno)
            return
        # 检查客户端的VLAN是否合法
        src_addr = byte_data[12:16]
        if not self.__vlan_ips or src_addr not in self.__vlan_ips:
            self.print_access_log("not_permit_vlan_ip")
            return
        if not self.fn_recv(pkt_len):
            self.delete_handler(self.fileno)
            return
        protocol = byte_data[9]
        if protocol == socket.IPPROTO_UDP:
            self.__udp_local_proxy_for_send(byte_data)
            return
        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_auth(self, auth_data):
        if not self.fn_auth(auth_data):
            self.print_access_log("auth_failed")
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__TIMEOUT)
        self.print_access_log("auth_ok")
        self.__auth_ok = True

    def __handle_ping(self):
        self.__send_pong()

    def __handle_pong(self):
        self.__is_sent_ping = False

    def __handle_dns(self, dns_msg):
        self.ctl_handler(self.fileno, self.__creator_fd, "request_dns", dns_msg)

    def __handle_read(self, action, byte_data):
        if action not in tunnel_tcp.ACTS:
            self.print_access_log("not_support_action_type")
            return
        if not self.__auth_ok and action != tunnel_tcp.ACT_AUTH: self.delete_handler(self.fileno)
        if action == tunnel_tcp.ACT_AUTH: self.__handle_auth(byte_data)
        if action == tunnel_tcp.ACT_DNS: self.__handle_dns(byte_data)
        if action == tunnel_tcp.ACT_PING: self.__handle_ping()
        if action == tunnel_tcp.ACT_PONG: self.__handle_pong()
        if action == tunnel_tcp.ACT_DATA: self.__handle_data(byte_data)

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__decrypt.input(rdata)
        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except tunnel_tcp.ProtoError:
                self.print_access_log("wrong_format_packet")
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.decrypt.get_pkt()
                if not pkt_info: break
                self.__handle_read(*pkt_info)
            ''''''
        return

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if self.__auth_ok and self.__is_sent_ping:
            self.print_access_log("conn_timeout")
            self.delete_handler(self.fileno)
            return

        if not self.__auth_ok:
            self.print_access_log("auth_timeout")
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, self.__TIMEOUT)
        self.__send_ping()

    def tcp_delete(self):
        # 对创建的UDP Handler进行清理
        dels = []
        for k, v in self.__udp_natp_to_fd.items(): dels.append(v)
        for f in dels: self.delete_handler(f)

        self.print_access_log("conn_close")
        self.unregister(self.fileno)
        self.close()
        self.fn_close()
        self.ctl_handler(self.fileno, self.__creator_fd, "del_conn")
        self.__put_alloc_vlan_ips()

    def message_from_handler(self, from_fd, byte_data):
        pkt_len = (byte_data[2] << 8) | byte_data[3]
        dst_addr = byte_data[16:20]
        if dst_addr not in self.__vlan_ips: return
        self.__send_data(pkt_len, byte_data, action=tunnel_tcp.ACT_DATA)

    def fn_auth(self, auth_data):
        """处理验证请求
        :return Boolean, True表示验证成功,False表示验证失败
        """
        return False

    def fn_recv(self, pkt_len):
        """处理接收
        ：:return Boolean, True表示继续,False表示不继续执行
        """
        return True

    def fn_send(self, pkt_len):
        """处理发送
        :return Boolean,True表示继续,False表示不继续执行
        """
        return True

    def fn_close(self):
        """处理连接关闭
        :return:
        """
        return

    def __send_dns(self, byte_data):
        pkt_len = len(byte_data)
        if self.__debug: self.print_access_log("send_dns")
        self.__send_data(pkt_len, byte_data, action=tunnel_tcp.ACT_DNS)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("response_dns", "udp_nat_del",): return False
        if cmd == "response_dns":
            dns_msg, = args
            self.__send_dns(dns_msg)
        if cmd == "udp_nat_del":
            uniq_id, lan_addr = args
            if uniq_id not in self.__udp_natp_to_fd: return
            del self.__udp_natp_to_fd[uniq_id]
        return

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__caddr
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def get_alloc_vlan_ips(self, cnt):
        """获取分配到的VLAN IP"""
        self.__vlan_ips = self.ctl_handler(self.fileno, self.__creator_fd, "get_vlan_ips", cnt)
        ips = []
        if not self.__vlan_ips: return None
        for ippkt in self.__vlan_ips: ips.append(socket.inet_ntoa(ippkt))
        return ips

    def __put_alloc_vlan_ips(self):
        self.ctl_handler(self.fileno, self.__creator_fd, "put_vlan_ips", self.__vlan_ips)
