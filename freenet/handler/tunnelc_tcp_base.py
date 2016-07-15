#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import fdslight_etc.fn_client as fnc_config
import socket, time, sys
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.lib.static_nat as static_nat
import freenet.lib.whitelist as udp_whitelist
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.checksum as checksum
import pywind.lib.timer as timer


class tunnelc_tcp_base(tcp_handler.tcp_handler):
    # 验证超时时间
    __AUTH_TIMEOUT = 10
    __TIMEOUT = 90

    __encrypt = None
    __decrypt = None

    __debug = None
    __is_sent_ping = False

    __static_nat = None
    __udp_whitelist = None
    __udp_proxy_map = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -1
    __dns_fd = -1
    __auth_ok = False

    __timer = None
    # 走隧道的IP超时时间
    __IP_TIMEOUT = 900

    __force_udp_global_clients = None
    __udp_no_proxy_clients = None
    __BUFSIZE = 16 * 1024

    def init_func(self, creator_fd, dns_fd, raw_socket_fd, whitelist, debug=False):
        taddr = fnc_config.configs["tcp_server_address"]
        s = socket.socket()

        self.set_socket(s)
        self.connect(taddr, 6)

        crypto_info = fnc_config.configs["tcp_crypto_module"]
        name = crypto_info["name"]
        args = crypto_info["args"]
        name = "freenet.lib.crypto.%s" % name

        __import__(name)
        m = sys.modules[name]

        self.__encrypt = m.encrypt(*args)
        self.__decrypt = m.decrypt(*args)
        self.__debug = debug
        self.__static_nat = static_nat.nat()
        self.__dns_fd = dns_fd
        self.__traffic_send_fd = raw_socket_fd
        self.__timer = timer.timer()
        self.__udp_proxy_map = {}

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

    def __handle_auth_ok(self):
        self.__auth_ok = True
        self.print_access_log("auth_ok")
        self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read)
        self.set_timeout(self.fileno, self.__TIMEOUT)

        n = utils.ip4s_2_number(self.getpeername()[0])
        fdsl_ctl.set_tunnel(self.__traffic_fetch_fd, n)

        self.dispatcher.ctunnel_ok()

        self.ctl_handler(self.fileno, self.__dns_fd, "as_tunnel_fd")
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_open")
        self.ctl_handler(self.fileno, self.__dns_fd, "set_filter_dev_fd", self.__traffic_fetch_fd)

    def __send_data(self, pkt_len, sent_data, action=tunnel_tcp.ACT_DATA):
        sent_pkt = self.__encrypt.build_packet(action, pkt_len, sent_data)
        # 丢弃阻塞的包
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        self.__encrypt.reset()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)

    def send_auth(self, request_data):
        self.__send_data(len(request_data), request_data, action=tunnel_tcp.ACT_AUTH)
        self.print_access_log("send_auth")

    def connect_ok(self):
        self.print_access_log("connect_ok")
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.fn_auth_request()
        self.set_timeout(self.fileno, self.__AUTH_TIMEOUT)

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def __send_ping(self):
        if self.__debug: self.print_access_log("send_ping")
        self.__send_data(0, b"", action=tunnel_tcp.ACT_PING)

    def __handle_auth(self, auth_data):
        if not self.fn_auth_response(auth_data):
            self.print_access_log("auth_failed")
            self.delete_handler(self.fileno)
            return
        self.__handle_auth_ok()

    def __handle_ping(self):
        self.__send_data(0, b"", action=tunnel_tcp.ACT_PONG)
        if self.__debug: self.print_access_log("send_pong")

    def __handle_pong(self):
        self.__is_sent_ping = False

    def __handle_data(self, resp_data):
        ip_ver = (resp_data[0] & 0xf0) >> 4
        if ip_ver != 4: return
        data_len = (resp_data[2] << 8) | resp_data[3]
        if len(resp_data) != data_len: self.print_access_log(
            "not_equal_pkt_len,real:%s,proto:%s" % (len(resp_data), data_len,))

        npkt = self.__static_nat.get_new_packet_for_lan(resp_data)
        if not npkt:
            self.print_access_log("cannot_found_lan_address:%s" % socket.inet_ntoa(resp_data[16:20]))
            return
        saddr = npkt[12:16]
        self.__timer.set_timeout(saddr, self.__IP_TIMEOUT)
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, npkt)

    def __handle_dns(self, dns_msg):
        self.send_message_to_handler(self.fileno, self.__dns_fd, dns_msg)

    def __handle_read(self, action, resp_data):
        if action not in tunnel_tcp.ACTS:
            self.print_access_log("not_support_action_type")
            return
        if not self.__auth_ok and action != tunnel_tcp.ACT_AUTH: self.delete_handler(self.fileno)
        if action == tunnel_tcp.ACT_AUTH: self.__handle_auth(resp_data)
        if action == tunnel_tcp.ACT_DNS: self.__handle_dns(resp_data)
        if action == tunnel_tcp.ACT_PING: self.__handle_ping()
        if action == tunnel_tcp.ACT_PONG: self.__handle_pong()
        if action == tunnel_tcp.ACT_DATA: self.__handle_data(resp_data)

    def __get_id(self, address):
        """根据地址生成唯一id"""
        return "%s-%s" % address

    def __local_udp_proxy_for_send(self, byte_data):
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
        if uniq_id not in self.__udp_proxy_map:
            fileno = self.create_handler(self.fileno, traffic_pass.udp_proxy,
                                         self.__traffic_send_fd, (saddr, sport,),
                                         uniq_id)
            self.__udp_proxy_map[uniq_id] = fileno
        else:
            fileno = self.__udp_proxy_map[uniq_id]
        self.send_message_to_handler(self.fileno, fileno, byte_data)

    def __send_dns(self, dns_msg):
        pkt_len = len(dns_msg)
        self.__send_data(pkt_len, dns_msg, action=tunnel_tcp.ACT_DNS)

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
        self.__static_nat.recyle_ips()
        if not fnc_config.configs["udp_global"]: self.__udp_whitelist.recycle_cache()
        if not self.is_conn_ok():
            self.print_access_log("connect_failed")
            self.delete_handler(self.fileno)
            return
        if self.__is_sent_ping and self.__auth_ok:
            self.print_access_log("timeout")
            self.delete_handler(self.fileno)
            return
        if self.__auth_ok:
            self.set_timeout(self.fileno, self.__TIMEOUT)
            self.__is_sent_ping = True
            self.__send_ping()
            tunnel_ips = self.__timer.get_timeout_names()
            for ip in tunnel_ips:
                n = utils.ip4b_2_number(ip)
                fdsl_ctl.tf_record_del(self.__traffic_fetch_fd, n)
                if self.__timer.exists(ip): self.__timer.drop(ip)
            return
        self.print_access_log("auth_timeout")
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        if self.is_conn_ok():
            self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_close")
            self.unregister(self.fileno)
            self.delete_handler(self.__traffic_fetch_fd)
        self.close()
        self.dispatcher.ctunnel_fail()

    def fn_auth_request(self):
        """验证请求,重写这个方法"""
        pass

    def fn_auth_response(self, byte_data):
        """验证响应,重写这个方法
        :param byte_data 响应数据
        :return Boolean, True表示验证成功,False表示验证失败
        """
        return True

    def fn_close(self):
        """关闭连接的一些处理,重写这个方法"""
        pass

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % fnc_config.configs["tcp_server_address"]
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def alloc_vlan_ips(self, ips):
        """分配虚拟IP地址"""
        if self.__debug: self.print_access_log("alloc_ip_list:%s" % str(ips))
        if len(ips) < 1:
            self.print_access_log("server_not_alloc_enough_ip")
            self.delete_handler(self.fileno)
            return
        self.__static_nat.add_virtual_ips(ips)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("request_dns", "udp_nat_del"): return
        if cmd == "request_dns":
            dns_msg, = args
            self.__send_dns(dns_msg)
        if cmd == "udp_nat_del":
            uniq_id, lan_addr = args
            if uniq_id in self.__udp_proxy_map: del self.__udp_proxy_map[uniq_id]
        return

    def __handle_traffic_from_lan(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver != 4: return
        protocol = byte_data[9]

        udp_proxy = False
        saddr = byte_data[12:16]

        if protocol == 17 and saddr in self.__force_udp_global_clients: udp_proxy = True

        # 处理UDP代理
        if protocol == 17 and not fnc_config.configs["udp_global"] and not udp_proxy:
            if self.__udp_whitelist.find(byte_data[16:20]) or (saddr in self.__udp_no_proxy_clients):
                self.__local_udp_proxy_for_send(byte_data)
                return
            ''''''
        npkt = self.__static_nat.get_new_packet_to_tunnel(byte_data)
        if not npkt:
            self.print_access_log("cannot_convert_pakcet_to_tunnel")
            return
        daddr = npkt[16:20]
        self.__timer.set_timeout(daddr, self.__IP_TIMEOUT)
        pkt_len = (npkt[2] << 8) | npkt[3]
        self.__send_data(pkt_len, npkt)

    def message_from_handler(self, from_fd, byte_data):
        if from_fd == self.__traffic_fetch_fd:
            self.__handle_traffic_from_lan(byte_data)
            return
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)
