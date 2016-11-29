#!/usr/bin/env python3
import socket, sys, time
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_udp as tunnel_proto
import freenet.lib.ipaddr as ipaddr
import pywind.evtframework.handler.udp_handler as udp_handler
import freenet.handler.traffic_pass as traffic_pass
import pywind.lib.timer as timer
import freenet.lib.checksum as checksum


class tunnels_udp_base(udp_handler.udp_handler):
    __debug = None
    __dns_server = None
    __raw_socket_fd = None

    __nat = None

    # 允许的客户端
    # {ipaddr:(session_id,{})}
    __sessions = None

    # 空闲的session
    __empty_sessions = None
    # session id计数
    __session_id_cnt = 1

    # 通过客户端的虚拟IP获取真实的IP信息
    __client_info_by_v_ip = None

    __timer = None

    __dns_fd = -1

    # 会话检查时间
    __SESSION_CHECK_TIMEOUT = 60
    # 系统轮询检查时间
    __LOOP_TIMEOUT = 10

    __tun_fd = -1
    __raw_socket_fd = -1
    __dns_fd = -1

    __crypto = None

    __debug = False

    def init_func(self, creator_fd, tun_fd, dns_fd, raw_socket_fd, nat, debug=True):
        self.__debug = debug
        config = fns_config.configs

        # 导入加入模块
        name = "freenet.lib.crypto.%s" % config["udp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        self.__crypto = m

        self.__empty_sessions = []
        self.__client_info_by_v_ip = {}
        self.__timer = timer.timer()
        self.__debug = debug
        self.__sessions = {}

        self.__nat = nat
        bind_address = fns_config.configs["udp_listen"]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.bind(bind_address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.__tun_fd = tun_fd
        self.__dns_fd = dns_fd
        self.__raw_socket_fd = raw_socket_fd

        if not self.__debug:
            sys.stdout = open(fns_config.configs["access_log"], "a+")
            sys.stderr = open(fns_config.configs["error_log"], "a+")

        self.fn_init()

        return self.fileno

    def __get_session_id(self):
        session_id = 0
        if len(self.__empty_sessions) > 20:
            session_id = self.__empty_sessions.pop(0)
            return session_id
        if self.__session_id_cnt != 65535:
            session_id = self.__session_id_cnt
            self.__session_id_cnt += 1
        return session_id

    def __handle_auth(self, body_data, address):
        """处理验证"""
        if not self.fn_auth(body_data, address):
            self.print_access_log("auth_failed", address)
            return

        self.print_access_log("auth_ok", address)

    def register_session(self, session_id, address):
        """ 注册会话
        :param address:客户端地址
        :param ip_set  list(string): 客户端的IP地址集合
        :return Boolean: True 表示注册成功,False表示注册失败
        """

        session_id = self.__get_session_id()
        if not session_id: return 0

        self.__sessions[session_id] = {"udp_nat_map": {}, "address": address}

        return session_id

    def unregister_session(self, session_id):
        """注销会话"""
        if session_id not in self.__sessions: return

        session=self.__sessions[session_id]
        udp_nat_map = session["udp_nat_map"]

        dels = []
        for udp_nat_id in udp_nat_map:
            fileno = udp_nat_map[udp_nat_id]
            dels.append(fileno)
        for f in dels: self.delete_handler(f)

        sts="%s:%s" % session["address"]
        self.print_access_log("close", sts)
        self.fn_delete(session_id)

        del self.__sessions[session_id]

    def __handle_dns(self, dns_msg, address):
        uniq_id = "%s-%s" % address
        self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", uniq_id, dns_msg)

    def __handle_close(self, address):
        self.unregister_session(address)

    def __handle_data(self, byte_data, address):
        if self.__debug: self.print_access_log("recv_data", address)
        try:
            length = (byte_data[2] << 8) | byte_data[3]
        except IndexError:
            return
        if length > 1500:
            self.print_access_log("error_pkt_length", address)
            return

        byte_data = byte_data[0:length]

        # print("recv:",byte_data)
        protocol = byte_data[9]
        # 只支持 ICMP,TCP,UDP协议
        if protocol not in (1, 6, 17,): return
        
        pkt_len = (byte_data[2] << 8) | byte_data[3]

        if not self.fn_recv(pkt_len, address):
            self.unregister_session(address)
            return

        if protocol == 17:
            self.__handle_udp_data(byte_data, address)
            return

        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_udp_data(self, byte_data, address):
        """对UDP协议进行特别处理,以实现CONE NAT模型
        """
        # flags = (byte_data[6] & 0xe0) >> 5
        # flag_df = (flags & 0x2) >> 1
        # flags_mf = flags & 0x1
        offset = ((byte_data[6] & 0x1f) << 5) | byte_data[7]

        # 说明不是第一个数据分包,那么就直接发送给raw socket
        if offset:
            L = list(byte_data)
            checksum.modify_address(b"\0\0\0\0", L, checksum.FLAG_MODIFY_SRC_IP)
            self.send_message_to_handler(self.fileno, self.__raw_socket_fd, bytes(L))
            return

        ihl = (byte_data[0] & 0x0f) * 4
        saddr = socket.inet_ntoa(byte_data[12:16])
        b = ihl
        e = ihl + 1
        sport = (byte_data[b] << 8) | byte_data[e]

        uniq_id = "%s-%s" % address
        session_cls = self.__sessions[uniq_id]

        udp_nat_map = session_cls.udp_nat_map

        uniq_nat_id = "%s-%s" % (saddr, sport)

        if uniq_nat_id not in udp_nat_map:
            fileno = self.create_handler(self.fileno, traffic_pass.udp_proxy,
                                         self.__raw_socket_fd,
                                         (saddr, sport,),
                                         uniq_id)
            udp_nat_map[uniq_nat_id] = fileno
        else:
            fileno = udp_nat_map[uniq_nat_id]

        self.send_message_to_handler(self.fileno, fileno, byte_data)

    def send_data(self, client_address, data_len, byte_data, action=tunnel_proto.ACT_DATA):
        pkt_len = (byte_data[2] << 8) | byte_data[3]
        uniq_id = "%s-%s" % client_address

        session_cls = self.__sessions[uniq_id]
        pkts = session_cls.encrypt_m.build_packets(action, pkt_len, byte_data)
        session_cls.encrypt_m.reset()

        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)

        if not self.fn_send(data_len, client_address):
            self.unregister_session(client_address)
            return

        if self.__debug: self.print_access_log("send_data", client_address)
        for pkt in pkts: self.sendto(pkt, client_address)

        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        uniq_id = "%s-%s" % address
        # 不允许的客户端只接丢弃包
        # session不存在的时候构建一个临时session

        crypto_args = fns_config.configs["udp_crypto_module"].get("args", ())
        if uniq_id not in self.__sessions:
            session_cls = _udp_session(self.__crypto, crypto_args)
        else:
            session_cls = self.__sessions[uniq_id]
        result = session_cls.decrypt_m.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if uniq_id not in self.__sessions and action != tunnel_proto.ACT_AUTH:
            self.print_access_log("illegal_packet", address)
            return

        if action not in tunnel_proto.ACTS:
            self.print_access_log("not_found_action", address)
            return

        if action == tunnel_proto.ACT_AUTH:
            self.__handle_auth(byte_data, address)
            return

        if uniq_id not in self.__sessions:
            self.print_access_log("not_permit_session", address)
            return

        if action == tunnel_proto.ACT_DATA:
            # 目前只支持IPv4协议
            ip_ver = (byte_data[0] & 0xf0) >> 4
            if ip_ver != 4:
                self.print_access_log("not_support_ipv%s" % ip_ver, address)
                return
            if len(byte_data) < 20:
                self.print_access_log("error_ip_pkt", address)
                return

        if action == tunnel_proto.ACT_DATA: self.__handle_data(byte_data, address)
        if action == tunnel_proto.ACT_DNS: self.__handle_dns(byte_data, address)

        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        self.fn_timeout()
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            if name in self.__sessions: pass
            ''''''
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

    def udp_error(self):
        self.delete_handler(self.fileno)

    def __send_dns(self, uniq_id, dns_msg):
        msg_len = len(dns_msg)
        session_cls = self.__sessions[uniq_id]
        pkts = session_cls.encrypt_m.build_packets(tunnel_proto.ACT_DNS, msg_len, dns_msg)
        session_cls.encrypt_m.reset()
        address = session_cls.address

        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)

        if not self.fn_send(msg_len, address):
            self.unregister_session(address)
            return

        if self.__debug: self.print_access_log("send_dns", address)
        for pkt in pkts: self.sendto(pkt, address)
        self.add_evt_write(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("udp_nat_del", "response_dns",): return False

        if cmd == "response_dns":
            uniq_id, dns_msg = args
            if uniq_id not in self.__sessions: return True
            self.__send_dns(uniq_id, dns_msg)
            return True

        uniq_id, vlan_address = args
        uniq_nat_id = "%s-%s" % vlan_address
        if uniq_id not in self.__sessions: return False
        session_cls = self.__sessions[uniq_id]
        udp_nat_map = session_cls.udp_nat_map

        if uniq_nat_id in udp_nat_map: del udp_nat_map[uniq_nat_id]
        return

    def get_encrypt(self, address):
        uniq_id = "%s-%s" % address
        session_cls = self.__sessions.get(uniq_id, None)
        if not session_cls: return None
        return session_cls.encrypt_m

    def get_decrypt(self, address):
        uniq_id = "%s-%s" % address
        session_cls = self.__sessions.get(uniq_id, None)
        if not session_cls: return None
        return session_cls.decrypt_m

    def print_access_log(self, text, address):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % address
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def message_from_handler(self, from_fd, byte_data):
        dst_addr = byte_data[16:20]
        if dst_addr not in self.__client_info_by_v_ip: return
        address = self.__client_info_by_v_ip[dst_addr]
        data_len = (byte_data[2] << 8) | byte_data[3]

        self.send_data(address, data_len, byte_data)

    def get_client_ips(self, n):
        results = []

        for i in range(n):
            try:
                ippkt = self.__nat.get_addr()
            except ipaddr.IpaddrNoEnoughErr:
                # 回收IP地址
                for ip in results:
                    pkt = socket.inet_aton(ip)
                    self.__nat.put_addr(pkt)
                    results = None
                break
            results.append(
                socket.inet_ntoa(ippkt)
            )

        return results

    def fn_init(self):
        """初始化一些设置,重写这个方法"""
        pass

    def fn_auth(self, byte_data, address):
        """重写验证方法
        :param byte_data
        :param address
        :return Tuple: True表示验证通过,False表示验证失败
        """
        return True

    def fn_recv(self, data_len, session_id):
        """接收客户端数据的时候调用此函数
        :param data_len: 数据长度
        :param session_id: 会话ID
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def fn_send(self, data_len, session_id):
        """发送数据的时候调用此函数
        :param data_len: 数据长度
        :param address: 会话ID
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def fn_delete(self, session_id):
        """删除会话的时候会调用此函数,用于资源的释放
        :param session_id:会话ID
        """
        pass

    def fn_timeout(self):
        """超时函数调用,可用于一些数据统计
        :param address:
        :return:
        """
        pass
