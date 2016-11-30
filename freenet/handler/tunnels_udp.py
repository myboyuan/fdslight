#!/usr/bin/env python3
import socket, sys, time
import fdslight_etc.fn_server as fns_config
import freenet.lib.base_proto.tunnel_udp as tunnel_proto
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer


class tunnels_udp_listener(udp_handler.udp_handler):
    __debug = None
    __sessions = None
    __timer = None

    __dns_fd = -1

    # 系统轮询检查时间
    __LOOP_TIMEOUT = 10

    __SESSION_TIMEOUT = 1200

    __tun_fd = -1
    __tun6_fd = -1

    __dns_fd = -1

    __encrypt = None
    __decrypt = None

    __debug = False

    __auth_module = None

    # 当前包的session id
    __cur_packet_session_id = None

    def init_func(self, creator_fd, tun_fd, tun6_fd, dns_fd, auth_module, debug=True, is_ipv6=False):
        self.__debug = debug
        config = fns_config.configs

        # 导入加入模块
        name = "freenet.lib.crypto.%s" % config["udp_crypto_module"]["name"]

        __import__(name)
        m = sys.modules.get(name, None)

        crypto_config = config["udp_crypto_module"]["configs"]

        self.__encrypt = m.encrypt()
        self.__decrypt = m.decrypt()

        self.__encrypt.config(crypto_config)
        self.__decrypt.config(crypto_config)

        self.__timer = timer.timer()
        self.__debug = debug
        self.__sessions = {}
        self.__auth_module = auth_module

        if is_ipv6:
            bind_address = fns_config.configs["udp6_listen"]
        else:
            bind_address = fns_config.configs["udp_listen"]

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.bind(bind_address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.__tun_fd = tun_fd
        self.__tun6_fd = tun6_fd
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
        self.dispatcher.bind_session_id(session_id, self.fileno, "udp")

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
        self.__auth_module.handle_close(session_id)
        self.dispatcher.unbind_session(session_id)

        del self.__sessions[session_id]

    def __handle_dns_request(self, session_id, dns_msg):
        self.ctl_handler(self.fileno, self.__dns_fd, "request_dns", session_id, dns_msg)

    def __handle_ipv4_data_from_tunnel(self, session_id, byte_data):
        # print("recv:",byte_data)
        protocol = byte_data[9]
        # 只支持 ICMP,TCP,UDP协议
        if protocol not in (1, 6, 17,): return

        if protocol == 17:
            self.__handle_udp_data_from_tunnel(session_id, byte_data)
            return

        self.ctl_handler(self.fileno, self.__tun_fd, "set_packet_session_id", session_id)
        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self, session_id, byte_data):
        pass

    def __handle_data_from_tunnel(self, session_id, byte_data):
        version = (byte_data[0] & 0xf0) >> 4
        if version not in (4, 6,): return
        if version == 4: self.__handle_ipv4_data_from_tunnel(session_id, byte_data)
        if version == 6: self.__handle_ipv4_data_from_tunnel(session_id, byte_data)

        if self.__debug: self.print_access_log("recv_data", self.__sessions[session_id])

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
        for pkt in pkts:
            if not self.__auth_module.handle_send(session_id, len(byte_data)): return
            self.sendto(pkt, address)

        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if self.dispatcher.is_bind_session(session_id):
            fileno, other = self.dispatcher.get_bind_session(session_id)
            if fileno != self.fileno and other == "tcp": self.delete_handler(fileno)

        if not self.__auth_module.handle_recv(session_id, len(byte_data)):
            if self.__session_exists(session_id): self.__unregister_session(session_id)
            return

        if action not in tunnel_proto.ACTS:
            self.print_access_log("not_found_action", address)
            return

        if session_id not in self.__sessions:
            self.__register_session(session_id, address)
        self.__modify_client_address(session_id, address)
        self.__timer.set_timeout(session_id, self.__SESSION_TIMEOUT)

        if action == tunnel_proto.ACT_DATA: self.__handle_data_from_tunnel(session_id, byte_data)
        if action == tunnel_proto.ACT_DNS: self.__handle_dns_request(session_id, byte_data)

        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()

        for name in names:
            if self.__timer.exists(name): self.__timer.drop(name)
            if name in self.__sessions:
                self.__unregister_session(name)
                self.__auth_module.handle_timing_task(b"")
            continue
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

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

        if not self.__auth_module.handle_send(session_id, len(dns_msg)): return

        if self.__debug: self.print_access_log("send_dns", address)
        for pkt in pkts: self.sendto(pkt, address)
        self.add_evt_write(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("response_dns", "msg_from_udp_proxy", "set_packet_session_id",): return False

        if cmd == "response_dns":
            session_id, dns_msg = args
            if session_id not in self.__sessions: return True
            self.__send_dns(session_id, dns_msg)
            return True
        if cmd == "set_packet_session_id":
            self.__cur_packet_session_id, = args
            return True

        session_id, msg = args
        if session_id not in self.__sessions: return True
        self.__send_data(session_id, msg)

        return True

    def print_access_log(self, text, address):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % address
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def message_from_handler(self, from_fd, byte_data):
        session_id = self.__cur_packet_session_id
        self.__send_data(session_id, byte_data)
