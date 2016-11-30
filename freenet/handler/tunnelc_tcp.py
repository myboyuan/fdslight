#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import fdslight_etc.fn_client as fnc_config
import socket, time, sys
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.lib.whitelist as udp_whitelist
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils

import pywind.lib.timer as timer


class tunnelc_tcp(tcp_handler.tcp_handler):
    __LOOP_TIMEOUT = 10

    __encrypt = None
    __decrypt = None

    __debug = None
    __udp_whitelist = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -1
    __traffic6_send_fd = -1

    __dns_fd = -1

    __timer = None

    __force_udp_global_clients = None
    __udp_no_proxy_clients = None
    __BUFSIZE = 16 * 1024

    __session_id = None

    __wait_sent = None

    def init_func(self, creator_fd, dns_fd, raw_socket_fd, raw6_socket_fd, whitelist, debug=False, is_ipv6=False):
        taddr = fnc_config.configs["tcp_server_address"]

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket()
        self.__wait_sent = []

        self.set_socket(s)
        self.connect(taddr, 6)

        crypto_info = fnc_config.configs["tcp_crypto_module"]
        name = crypto_info["name"]
        name = "freenet.lib.crypto.%s" % name

        __import__(name)
        m = sys.modules[name]

        self.__encrypt = m.encrypt()
        self.__decrypt = m.decrypt()

        self.__encrypt.config(crypto_info["configs"])
        self.__decrypt.config(crypto_info["configs"])

        self.__debug = debug

        account = fnc_config.configs["account"]
        self.__session_id = proto_utils.gen_session_id(account["username"], account["password"])

        self.__dns_fd = dns_fd
        self.__traffic_send_fd = raw_socket_fd
        self.__traffic6_send_fd = raw6_socket_fd
        self.__timer = timer.timer()

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

        return self.fileno

    def __send_data(self, sent_data, action=tunnel_tcp.ACT_DATA):
        sent_pkt = self.__encrypt.build_packet(self.__session_id, action, sent_data)
        # 丢弃阻塞的包
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        self.__encrypt.reset()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)

    def connect_ok(self):
        self.print_access_log("connect_ok")

        self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read)

        n = utils.ip4s_2_number(self.getpeername()[0])
        fdsl_ctl.set_tunnel(self.__traffic_fetch_fd, n)

        self.dispatcher.ctunnel_ok()
        self.dispatcher.bind_session_id(self.__session_id, self.fileno, "tcp")

        self.ctl_handler(self.fileno, self.__dns_fd, "as_tunnel_fd")
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_open")
        self.ctl_handler(self.fileno, self.__dns_fd, "set_filter_dev_fd", self.__traffic_fetch_fd)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        while 1:
            try:
                is_dns, msg = self.__wait_sent.pop(0)
            except IndexError:
                break
            if is_dns:
                self.__send_dns(msg)
            else:
                self.__send_data(msg)
            continue
        return

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def __handle_data_from_tunnel(self, resp_data):
        ip_ver = (resp_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        if ip_ver == 4: self.__handle_ipv4_data_from_tunnel(resp_data)
        if ip_ver == 6: self.__handle_ipv6_data_from_tunnel(resp_data)

    def __handle_ipv4_data_from_tunnel(self, byte_data):
        data_len = (byte_data[2] << 8) | byte_data[3]

        if len(byte_data) != data_len:
            self.print_access_log("wrong_packet_length")
            return
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self, byte_data):
        pass

    def __handle_dns(self, dns_msg):
        self.send_message_to_handler(self.fileno, self.__dns_fd, dns_msg)

    def __handle_read(self, action, resp_data):
        if action not in tunnel_tcp.ACTS:
            self.print_access_log("not_support_action_type")
            return
        if action == tunnel_tcp.ACT_DNS: self.__handle_dns(resp_data)
        if action == tunnel_tcp.ACT_DATA: self.__handle_data_from_tunnel(resp_data)

    def __send_dns(self, dns_msg):
        self.__send_data(dns_msg, action=tunnel_tcp.ACT_DNS)

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

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.print_access_log("disconnect")
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        self.unregister(self.fileno)
        if self.is_conn_ok():
            self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_close")
            self.unregister(self.fileno)
            self.delete_handler(self.__traffic_fetch_fd)
        self.close()
        self.dispatcher.ctunnel_fail()

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % fnc_config.configs["tcp_server_address"]
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("request_dns",): return
        if cmd == "request_dns":
            dns_msg, = args
            if not self.connect_ok():
                self.__wait_sent.append((1, dns_msg))
                return
            self.__send_dns(dns_msg)
        return

    def __handle_ipv4_traffic_from_lan(self, byte_data):
        protocol = byte_data[9]

        udp_proxy = False
        saddr = byte_data[12:16]

        if protocol == 17 and saddr in self.__force_udp_global_clients: udp_proxy = True

        # 处理UDP代理
        if protocol == 17 and not fnc_config.configs["udp_global"] and not udp_proxy:
            if self.__udp_whitelist.find(byte_data[16:20]) or (saddr in self.__udp_no_proxy_clients):
                self.dispatcher.send_msg_to_udp_proxy(self.__session_id, byte_data)
                return
            ''''''
        self.__send_data(byte_data)

    def __handle_ipv6_traffic_from_lan(self, byte_data):
        pass

    def __handle_traffic_from_lan(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        if ip_ver == 4: self.__handle_ipv4_traffic_from_lan(byte_data)
        if ip_ver == 6: self.__handle_traffic_from_lan(byte_data)

    def message_from_handler(self, from_fd, byte_data):
        if from_fd == self.__traffic_fetch_fd:
            if not self.connect_ok():
                self.__wait_sent.append((0, byte_data), )
                return
            self.__handle_traffic_from_lan(byte_data)
            return
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)
