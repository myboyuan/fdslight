#!/usr/bin/env python3
import socket, sys, time
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_udp as tunnel_proto
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer


class tunnels_udp_base(udp_handler.udp_handler):
    __debug = None
    __dns_server = None

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

    # 系统轮询检查时间
    __LOOP_TIMEOUT = 10

    __tun_fd = -1
    __dns_fd = -1

    __encrypt = None
    __decrypt = None

    __debug = False

    def init_func(self, creator_fd, tun_fd, dns_fd, nat, debug=True):
        self.__debug = debug
        config = fns_config.configs

        # 导入加入模块
        name = "freenet.lib.crypto.%s" % config["udp_crypto_module"]["name"]
        crypto_args = fns_config.configs["udp_crypto_module"].get("args", ())
        __import__(name)
        m = sys.modules.get(name, None)

        self.__encrypt = m.encrypt(crypto_args)
        self.__decrypt = m.decrypt(crypto_args)

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

        if not self.__debug:
            sys.stdout = open(fns_config.configs["access_log"], "a+")
            sys.stderr = open(fns_config.configs["error_log"], "a+")

        self.fn_init()

        return self.fileno

    def __register_session(self, session_id, address):
        """ 注册会话
        :param address:客户端地址
        :param ip_set  list(string): 客户端的IP地址集合
        :return Boolean: True 表示注册成功,False表示注册失败
        """
        if session_id in self.__sessions: return
        self.__sessions[session_id] = address
        self.dispatcher.bind_session_id(session_id, self.fileno)

    def __modify_client_address(self, session_id, address):
        """修改客戶端地址,客戶端的端口和地址可能发生改变，为了确保数据到达，
        因此需要调用此函数
        """
        if session_id not in self.__sessions: return
        self.__sessions[session_id] = address

    def __session_exists(self, session_id):
        """会话是否存在"""
        return session_id in self.__sessions

    def __unregister_session(self, session_id):
        """注销会话"""
        if session_id not in self.__sessions: return

        address = self.__sessions[session_id]
        sts = "%s:%s" % address

        self.print_access_log("disconnect", sts)
        self.fn_delete(session_id)

        del self.__sessions[session_id]

    def __handle_dns_request(self, session_id, dns_msg):
        self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", session_id, dns_msg)

    def __handle_close(self, address):
        self.unregister_session(address)

    def __handle_ipv4_data_from_tunnel(self, session_id, byte_data):
        # print("recv:",byte_data)
        protocol = byte_data[9]
        # 只支持 ICMP,TCP,UDP协议
        if protocol not in (1, 6, 17,): return

        pkt_len = (byte_data[2] << 8) | byte_data[3]

        if not self.fn_recv(pkt_len, session_id):
            self.unregister_session(session_id)
            return
        if protocol == 17:
            self.__handle_udp_data(byte_data, session_id)
            return
        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_data_from_tunnel(self, byte_data, address):
        if self.__debug: self.print_access_log("recv_data", address)
        try:
            length = (byte_data[2] << 8) | byte_data[3]
        except IndexError:
            return
        if length > 1500:
            self.print_access_log("error_pkt_length", address)
            return

    def __handle_udp_data_from_tunnel(self, session_id, byte_data):
        """对UDP协议进行特别处理,以实现CONE NAT模型
        """
        self.dispatcher.send_msg_to_udp_proxy(session_id, byte_data)

    def __send_data(self, session_id, byte_data):
        try:
            address = self.__sessions[session_id]
        except KeyError:
            return

        pkts = self.__encrypt.build_packets(session_id, tunnel_proto.ACT_DATA, byte_data)
        self.__encrypt.reset()

        sts = "%s:%s" % address
        if self.__debug: self.print_access_log("send_dns", sts)
        for pkt in pkts: self.sendto(pkt, address)

        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        uniq_id = "%s-%s" % address
        # 不允许的客户端只接丢弃包
        # session不存在的时候构建一个临时session

        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if action not in tunnel_proto.ACTS:
            self.print_access_log("not_found_action", address)
            return

        if action == tunnel_proto.ACT_DATA: self.__handle_data_from_tunnel(byte_data, address)
        if action == tunnel_proto.ACT_DNS: self.__handle_dns_request(byte_data, address)

        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            if name in self.__sessions: pass
            ''''''
        self.fn_timeout()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__nat.recycle()

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

    def udp_error(self):
        self.delete_handler(self.fileno)

    def __send_dns(self, session_id, dns_msg):
        try:
            address = self.__sessions[session_id]
        except KeyError:
            return

        pkts = self.__encrypt.build_packets(session_id, tunnel_proto.ACT_DNS, dns_msg)
        self.__encrypt.reset()

        if not self.fn_send(len(dns_msg), address):
            self.unregister_session(session_id)
            return

        if self.__debug: self.print_access_log("send_dns", address)
        for pkt in pkts: self.sendto(pkt, address)
        self.add_evt_write(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("response_dns", "msg_from_udp_proxy"): return False

        if cmd == "response_dns":
            session_id, dns_msg = args
            if session_id not in self.__sessions: return True
            self.__send_dns(session_id, dns_msg)
            return True

        session_id, msg = args
        if session_id not in self.__sessions: return
        self.__send_data(session_id, msg)

        return

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

        self.__send_dns(address, data_len, byte_data)

    def fn_init(self):
        """初始化一些设置,重写这个方法"""
        pass

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
