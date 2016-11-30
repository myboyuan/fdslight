#!/usr/bin/env python3
"""
隧道客户端基本类
"""
import socket, sys, time
import fdslight_etc.fn_client as fnc_config
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import freenet.lib.base_proto.tunnel_udp as tunnel_proto
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.whitelist as udp_whitelist


class tunnelc_udp(udp_handler.udp_handler):
    __server = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -2
    __traffic6_send_fd = -2

    __dns_fd = -1

    __encrypt_m = None
    __decrypt_m = None

    __session_id = None

    __debug = False

    # 服务端IP地址
    __server_ipaddr = None
    # UDP白名单部分相关变量
    __udp_whitelist = None

    __timer = None

    # 如果超过这个时间,那么将会从内核过滤器中删除
    __IP_TIMEOUT = 1200

    __force_udp_global_clients = None
    __udp_no_proxy_clients = None

    __LOOP_TIMEOUT = 10

    def init_func(self, creator_fd, dns_fd, raw_socket_fd, raw6_socket_fd, whitelist, debug=False, is_ipv6=False):
        self.__server = fnc_config.configs["udp_server_address"]

        name = "freenet.lib.crypto.%s" % fnc_config.configs["udp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_config = fnc_config.configs["udp_crypto_module"]["configs"]

        self.__encrypt_m = m.encrypt()
        self.__decrypt_m = m.decrypt()

        self.__encrypt_m.config(crypto_config)
        self.__decrypt_m.config(crypto_config)

        self.__debug = debug
        self.__timer = timer.timer()

        account = fnc_config.configs["account"]
        self.__session_id = proto_utils.gen_session_id(account["username"], account["password"])

        self.__traffic_send_fd = raw_socket_fd
        self.__traffic6_send_fd = raw6_socket_fd

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.__dns_fd = dns_fd
        self.dispatcher.bind_session_id(self.__session_id,self.fileno,"udp")

        try:
            self.connect(self.__server)
        except socket.gaierror:
            self.dispatcher.tunnel_fail()
            return -1

        ipaddr, _ = s.getpeername()

        self.__server_ipaddr = ipaddr

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        # 如果是非全局UDP代理,那么开启UDP白名单模式
        if not fnc_config.configs["udp_global"]:
            self.__udp_whitelist = udp_whitelist.whitelist()
            for subn, mask in whitelist: self.__udp_whitelist.add_rule(subn, mask)

        if not self.__debug:
            sys.stdout = open(fnc_config.configs["access_log"], "a+")
            sys.stderr = open(fnc_config.configs["error_log"], "a+")

        self.__force_udp_global_clients = {}
        self.__udp_no_proxy_clients = {}
        for client_ip in fnc_config.configs["udp_force_global_clients"]:
            saddr = socket.inet_aton(client_ip)
            self.__force_udp_global_clients[saddr] = None
        for client_ip in fnc_config.configs["udp_no_proxy_clients"]:
            saddr = socket.inet_aton(client_ip)
            self.__udp_no_proxy_clients[saddr] = None

        self.__session_id = self.fn_get_session_id()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        return self.fileno

    def __handle_data(self, byte_data):
        try:
            length = (byte_data[2] << 8) | byte_data[3]
        except IndexError:
            return
        if length > 1500:
            self.print_access_log("error_pkt_length:%s,real_length:%s" % (length, len(byte_data),))
            return
        if length != len(byte_data):
            self.print_access_log("error_length_not_match:%s,real_length:%s" % (length, len(byte_data),))
            return
        byte_data = byte_data[0:length]
        p = byte_data[9]

        # print("recv:",byte_data)
        # 过滤到不支持的协议
        if p not in (1, 6, 17,): return

        return

    def __handle_close(self):
        # 先删除流量过滤handler,保证其它流量能够走客户端默认路由
        self.print_access_log("close_connect")
        self.delete_handler(self.fileno)

    def __init(self):
        self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read)
        n = utils.ip4s_2_number(self.__server_ipaddr)
        fdsl_ctl.set_tunnel(self.__traffic_fetch_fd, n)

        self.dispatcher.tunnel_ok()

        self.ctl_handler(self.fileno, self.__dns_fd, "as_tunnel_fd")
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_open")
        self.ctl_handler(self.fileno, self.__dns_fd, "set_filter_dev_fd", self.__traffic_fetch_fd)

        return

    def set_session_id(self, sid):
        self.encrypt.set_session_id(sid)

    def __send_data(self, byte_data, action=tunnel_proto.ACT_DATA):
        # if self.__debug: self.print_access_log("send_data")
        try:
            ippkts = self.__encrypt_m.build_packets(self.__session_id, action, byte_data)
            self.__encrypt_m.reset()
        except ValueError:
            return
        # print("send:", byte_data)
        for ippkt in ippkts: self.send(ippkt)

        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        result = self.__decrypt_m.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if action not in tunnel_proto.ACTS:
            self.print_access_log("can_not_found_action_%s" % action)
            return

        if action == tunnel_proto.ACT_DATA: self.__handle_data(byte_data)
        if action == tunnel_proto.ACT_DNS: self.send_message_to_handler(self.fileno, self.__dns_fd, byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.print_access_log("server_down")
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        if not fnc_config.configs["udp_global"]: self.__udp_whitelist.recycle_cache()
        filter_ips = self.__timer.get_timeout_names()

        for ip in filter_ips:
            n = utils.ip4b_2_number(ip)
            fdsl_ctl.tf_record_del(self.__traffic_fetch_fd, n)
            if self.__timer.exists(ip): self.__timer.drop(ip)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__handle_close()

    def udp_delete(self):
        self.unregister(self.fileno)
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_close")
        self.unregister(self.fileno)
        self.delete_handler(self.__traffic_fetch_fd)
        self.socket.close()
        self.dispatcher.ctunnel_fail()

    @property
    def encrypt(self):
        return self.__encrypt_m

    @property
    def decrypt(self):
        return self.__decrypt_m

    def __udp_local_proxy_for_send(self, byte_data):
        self.dispatcher.send_msg_to_udp_proxy(self.__session_id, byte_data)

    def __handle_ipv4_traffic_from_lan(self, byte_data):
        protocol = byte_data[9]

        udp_proxy = False
        saddr = byte_data[12:16]

        if protocol == 17 and saddr in self.__force_udp_global_clients: udp_proxy = True
        # 处理UDP代理
        if protocol == 17 and not fnc_config.configs["udp_global"] and not udp_proxy:
            if self.__udp_whitelist.find(byte_data[16:20]) or (saddr in self.__udp_no_proxy_clients):
                self.__udp_local_proxy_for_send(byte_data)
                return
            ''''''
        self.__send_data(byte_data)

    def __handle_ipv6_traffic_from_lan(self, byte_data):
        pass

    def __handle_traffic_from_lan(self, byte_data):
        version = (byte_data[0] & 0xf0) >> 4
        if version not in (4, 6,): return
        if version == 4: self.__handle_ipv4_traffic_from_lan(byte_data)
        if version == 6: self.__handle_ipv6_traffic_from_lan(byte_data)

    def message_from_handler(self, from_fd, byte_data):
        # 处理来自local udp proxy的数据
        if from_fd != self.__traffic_fetch_fd:
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)
            return
        self.__handle_traffic_from_lan(byte_data)

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__server
        echo = "%s        %s         %s" % (text, addr, t)

        print(echo)
        sys.stdout.flush()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("msg_from_udp_proxy", "request_dns",): return False
        if cmd == "request_dns":
            dns_msg, = args
            self.__send_data(dns_msg, action=tunnel_proto.ACT_DNS)
            return True
        session_id, msg = args
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, msg)

    def fn_get_session_id(self):
        """重写这个方法"""
        return bytes(16)
