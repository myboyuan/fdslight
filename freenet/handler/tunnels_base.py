#!/usr/bin/env python3
import socket, sys, time
import fdslight_etc.fn_server as fns_config
import freenet.handler.tundev as tundev
import freenet.lib.base_proto.tunnel as tunnel_proto
import freenet.lib.ipaddr as ipaddr
import pywind.evtframework.handler.udp_handler as udp_handler
import freenet.handler.traffic_pass as traffic_pass
import pywind.lib.timer as timer
import freenet.lib.checksum as checksum


class _udp_session(object):
    session_id = 0
    # sent ping计数
    sent_ping_cnt = 0
    client_ips = None
    address = None
    udp_nat_map = None

    decrypt_m = None
    encrypt_m = None

    def __init__(self, sec_mod, mod_args):
        self.client_ips = {}
        self.udp_nat_map = {}
        self.decrypt_m = sec_mod.decrypt(*mod_args)
        self.encrypt_m = sec_mod.encrypt(*mod_args)


class tunnels_base(udp_handler.udp_handler):
    __debug = None
    __dns_server = None
    __raw_socket_fd = None

    __ipalloc = None

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
    __TIMEOUT = 60

    __tun_fd = -1
    __raw_socket_fd = -1

    __crypto = None

    __debug = False

    def init_func(self, creator_fd, debug=True):
        self.__debug = debug
        config = fns_config.configs

        # 导入加入模块
        name = "freenet.lib.crypto.%s" % config["crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        self.__crypto = m

        self.__empty_sessions = []
        self.__client_info_by_v_ip = {}
        self.__timer = timer.timer()
        self.__debug = debug
        self.__sessions = {}

        subnet = config["subnet"]
        self.__ipalloc = ipaddr.ip4addr(*subnet)
        bind_address = fns_config.configs["bind_address"]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.bind(bind_address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__TIMEOUT)

        self.__tun_fd = self.create_handler(self.fileno, tundev.tuns, "fdslight", subnet)
        self.__raw_socket_fd = self.create_handler(self.fileno, traffic_pass.traffic_send)

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

    def register_session(self, address, ip_set):
        """ 注册会话
        :param address:客户端地址
        :param ip_set  list(string): 客户端的IP地址集合
        :return Boolean: True 表示注册成功,False表示注册失败
        """
        tmpdict = {}
        uniq_id = "%s-%s" % address

        for s in ip_set:
            ippkt = socket.inet_aton(s)
            tmpdict[ippkt] = None
            self.__client_info_by_v_ip[ippkt] = address

        session_id = self.__get_session_id()
        if not session_id: return 0

        crypto_args = fns_config.configs["crypto_module"].get("args", ())
        session_cls = _udp_session(self.__crypto, crypto_args)

        session_cls.session_id = session_id
        session_cls.client_ips = tmpdict
        session_cls.address = address
        session_cls.encrypt_m.set_session_id(session_id)

        self.__sessions[uniq_id] = session_cls
        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)

        return session_id

    def get_session(self, address):
        uniq_id = "%s-%s" % address
        return self.__sessions.get(uniq_id, None)

    def unregister_session(self, address):
        """注销会话"""
        uniq_id = "%s-%s" % address
        if uniq_id not in self.__sessions: return
        session_cls = self.__sessions[uniq_id]

        for client_ip in session_cls.client_ips:
            self.__ipalloc.put_addr(client_ip)
            if client_ip in self.__client_info_by_v_ip: del self.__client_info_by_v_ip[client_ip]

        udp_nat_map = session_cls.udp_nat_map

        for udp_nat_id in udp_nat_map:
            fileno = udp_nat_map[udp_nat_id]
            self.delete_handler(fileno)

        session_cls.udp_nat_map = None
        self.print_access_log("close", address)
        self.fn_delete(address)

        del self.__sessions[uniq_id]

    def __send_ping(self, address):
        uniq_id = "%s-%s" % address
        session_cls = self.__sessions[uniq_id]
        session_cls.sent_ping_cnt += 1

        ping = session_cls.encrypt_m.build_ping()
        session_cls.encrypt_m.reset()

        if self.__debug: self.print_access_log("send_ping", address)

        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)
        self.add_evt_write(self.fileno)
        self.sendto(ping, address)

    def __send_pong(self, address):
        uniq_id = "%s-%s" % address
        session_cls = self.__sessions[uniq_id]

        pong = session_cls.encrypt_m.build_pong()
        session_cls.encrypt_m.reset()

        if self.__debug: self.print_access_log("send_pong", address)
        session_cls.sent_ping_cnt = 0
        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)

        self.add_evt_write(self.fileno)
        self.sendto(pong, address)

    def __handle_ping(self, address):
        if self.__debug: self.print_access_log("received_ping", address)
        self.__send_pong(address)

    def __handle_pong(self, address):
        uniq_id = "%s-%s" % address
        session_cls = self.__sessions[uniq_id]
        session_cls.sent_ping_cnt = 0

        if self.__debug: self.print_access_log("received_pong", address)

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

        print("recv:",byte_data)
        protocol = byte_data[9]
        # 只支持 ICMP,TCP,UDP协议
        if protocol not in (1, 6, 17,):
            self.print_access_log("not_support_IP_protocol", address)
            return
        pkt_len = (byte_data[2] << 8) | byte_data[3]

        if not self.fn_recv(pkt_len, address):
            self.unregister_session(address)
            return

        uniq_id = "%s-%s" % address
        self.__timer.set_timeout(uniq_id, self.__SESSION_CHECK_TIMEOUT)

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

        print("send:",byte_data)
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

    def send_auth(self, address, byte_data):
        crypto_args = fns_config.configs["crypto_module"].get("args", ())
        tmp_encrypt = self.__crypto.encrypt(*crypto_args)
        pkts = tmp_encrypt.build_packets(tunnel_proto.ACT_AUTH, len(byte_data), byte_data)
        self.print_access_log("send_auth", address)

        for pkt in pkts:
            self.sendto(pkt, address)
        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        uniq_id = "%s-%s" % address
        # 不允许的客户端只接丢弃包
        # session不存在的时候构建一个临时session

        crypto_args = fns_config.configs["crypto_module"].get("args", ())
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

            # 会话ID与IP地址不一致,删除数据
        if session_cls.session_id != session_id:
            self.print_access_log("error_session_code_%s" % session_id, address)
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
            src_addr = byte_data[12:16]
            # 检查客户端是否随意伪造分配到的IP
            if src_addr not in session_cls.client_ips:
                self.print_access_log("illegal_client_vlan_ip_%s" % socket.inet_ntoa(src_addr), address)
                return

        if action == tunnel_proto.ACT_PING: self.__handle_ping(address)
        if action == tunnel_proto.ACT_PONG: self.__handle_pong(address)
        if action == tunnel_proto.ACT_DATA: self.__handle_data(byte_data, address)

        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            if name in self.__sessions:
                session_cls = self.__sessions[name]
                if session_cls.sent_ping_cnt > 8:
                    self.unregister_session(session_cls.address)
                else:
                    self.__send_ping(session_cls.address)
                ''''''
            ''''''
        self.set_timeout(self.fileno, self.__TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

    def udp_error(self):
        self.delete_handler(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "udp_nat_del": return False
        uniq_id, vlan_address = args

        uniq_nat_id = "%s-%s" % vlan_address
        if uniq_id not in self.__sessions: return False
        session_cls = self.__sessions[uniq_id]
        udp_nat_map = session_cls.udp_nat_map

        if uniq_nat_id in udp_nat_map:
            fileno = udp_nat_map[uniq_nat_id]
            self.delete_handler(fileno)
            del udp_nat_map[uniq_nat_id]

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
                ippkt = self.__ipalloc.get_addr()
            except ipaddr.IpaddrNoEnoughErr:
                # 回收IP地址
                for ip in results:
                    pkt = socket.inet_aton(ip)
                    self.__ipalloc.put_addr(pkt)
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

    def fn_recv(self, data_len, address):
        """接收客户端数据的时候调用此函数
        :param data_len: 数据长度
        :param address: 客户端地址
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def fn_send(self, data_len, address):
        """发送数据的时候调用此函数
        :param data_len: 数据长度
        :param address: 目标地址
        :return Boolean: True表示继续执行,False表示中断执行
        """
        return True

    def fn_delete(self, address):
        """删除会话的时候会调用此函数,用于资源的释放
        :param address :客户端地址
        """
        pass
