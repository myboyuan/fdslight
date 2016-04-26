#!/usr/bin/env python3
"""
隧道客户端基本类
"""
import socket, sys, time, random
import fdslight_etc.fn_client as fnc_config
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import freenet.lib.checksum as checksum
import freenet.lib.base_proto.tunnel_udp as tunnel_proto
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.static_nat as static_nat
import freenet.lib.whitelist as udp_whitelist


class tunnelc_udp_base(udp_handler.udp_handler):
    __nat = None
    __server = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -2
    __dns_fd = -1

    __encrypt_m = None
    __decrypt_m = None

    __TIMEOUT_NO_AUTH = 5
    __session_id = 0

    __is_auth = False

    # 发送ping的次数
    __sent_ping_cnt = 0
    __debug = False

    # 服务端IP地址
    __server_ipaddr = None
    # UDP白名单部分相关变量
    __udp_whitelist = None
    __udp_proxy_map = None

    __timer = None
    # 如果超过这个时间,那么将会从内核过滤器中删除
    __IP_TIMEOUT = 300

    @property
    def __TIMEOUT(self):
        return random.randint(1, 30)

    def init_func(self, creator_fd, dns_fd, whitelist, debug=False):
        self.__nat = static_nat.nat()
        self.__server = fnc_config.configs["udp_server_address"]

        name = "freenet.lib.crypto.%s" % fnc_config.configs["udp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_args = fnc_config.configs["udp_crypto_module"].get("args", ())
        self.__encrypt_m = m.encrypt(*crypto_args)
        self.__decrypt_m = m.decrypt(*crypto_args)

        self.__debug = debug
        self.__timer = timer.timer()

        self.__traffic_send_fd = self.create_handler(self.fileno, traffic_pass.traffic_send)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.__dns_fd = dns_fd

        try:
            self.connect(self.__server)
        except socket.gaierror:
            self.dispatcher.ctunnel_fail()
            return -1

        ipaddr, _ = s.getpeername()

        self.__server_ipaddr = ipaddr

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__udp_proxy_map = {}
        # 如果是非全局UDP代理,那么开启UDP白名单模式
        if not fnc_config.configs["udp_global"]:
            self.__udp_whitelist = udp_whitelist.whitelist()
            for subn, mask in whitelist: self.__udp_whitelist.add_rule(subn, mask)

        if not self.__debug:
            sys.stdout = open(fnc_config.configs["access_log"], "a+")
            sys.stderr = open(fnc_config.configs["error_log"], "a+")

        self.fn_init()
        self.fn_auth_request()
        self.set_timeout(self.fileno, self.__TIMEOUT_NO_AUTH)

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
        if p not in (1, 6, 17, 132,): return

        new_pkt = self.__nat.get_new_packet_for_lan(byte_data)
        if not new_pkt:
            self.print_access_log("cant_not_send_packet_to_lan_%s" % socket.inet_ntoa(byte_data[16:20]))
            return

        # if self.__debug: self.print_access_log("recv_data")
        self.set_timeout(self.fileno, self.__TIMEOUT)
        src_addr = new_pkt[12:16]
        self.__timer.set_timeout(src_addr, self.__IP_TIMEOUT)
        self.send_message_to_handler(self.fileno, self.__traffic_send_fd, new_pkt)
        return

    def __handle_close(self):
        # 先删除流量过滤handler,保证其它流量能够走客户端默认路由
        self.print_access_log("close_connect")
        self.delete_handler(self.__traffic_fetch_fd)
        self.__is_auth = False
        self.__traffic_fetch_fd = -1
        self.__nat.reset()
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_close")
        self.set_timeout(self.fileno, self.__TIMEOUT_NO_AUTH)

    def __handle_auth_ok(self, session_id):
        self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read)
        n = utils.ip4s_2_number(self.__server_ipaddr)
        fdsl_ctl.set_tunnel(self.__traffic_fetch_fd, n)

        self.__is_auth = True
        self.dispatcher.ctunnel_ok()

        self.ctl_handler(self.fileno, self.__dns_fd, "as_tunnel_fd")
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_open")
        self.ctl_handler(self.fileno, self.__dns_fd, "set_filter_dev_fd", self.__traffic_fetch_fd)

        self.set_timeout(self.fileno, self.__TIMEOUT)
        return

    def set_session_id(self, sid):
        self.encrypt.set_session_id(sid)

    def send_data(self, pkt_len, byte_data, action=tunnel_proto.ACT_DATA):
        # if self.__debug: self.print_access_log("send_data")
        try:
            ippkts = self.__encrypt_m.build_packets(action, pkt_len, byte_data)
            self.__encrypt_m.reset()
        except ValueError:
            return
        # print("send:", byte_data)
        for ippkt in ippkts: self.send(ippkt)

        if self.__is_auth: self.set_timeout(self.fileno, self.__TIMEOUT)

        self.add_evt_write(self.fileno)

    def send_auth(self, auth_data):
        self.print_access_log("send_auth")
        self.send_data(len(auth_data), auth_data, action=tunnel_proto.ACT_AUTH)

    def __send_ping(self):
        if self.__debug: self.print_access_log("send_ping")

        ping = self.__encrypt_m.build_ping()
        self.__encrypt_m.reset()

        self.__sent_ping_cnt += 1
        self.send(ping)
        self.add_evt_write(self.fileno)

    def __send_pong(self):
        if self.__debug: self.print_access_log("send_pong")
        pong = self.__encrypt_m.build_pong()
        self.__encrypt_m.reset()

        self.send(pong)
        self.add_evt_write(self.fileno)
        self.__sent_ping_cnt = 0
        self.set_timeout(self.fileno, self.__TIMEOUT)

    def __send_close(self):
        if self.__debug: self.print_access_log("send_close")
        close = self.__encrypt_m.build_close()
        self.__encrypt_m.reset()

        self.send(close)
        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        result = self.__decrypt_m.parse(message)
        if not result: return

        session_id, action, byte_data = result

        if action not in tunnel_proto.ACTS:
            self.print_access_log("can_not_found_action_%s" % action)
            return

        if not self.__is_auth and tunnel_proto.ACT_AUTH != action: return

        if action == tunnel_proto.ACT_AUTH:
            ret = self.fn_auth_response(byte_data)
            if not ret:
                self.print_access_log("auth_failed")
                return
            self.print_access_log("auth_ok")
            self.__handle_auth_ok(session_id)

        if action == tunnel_proto.ACT_CLOSE: self.__handle_close()
        if action == tunnel_proto.ACT_PING:
            if self.__debug: self.print_access_log("received_ping")
            self.__send_pong()
        if action == tunnel_proto.ACT_PONG:
            if self.__debug: self.print_access_log("received_pong")
            self.__sent_ping_cnt = 0
        if action == tunnel_proto.ACT_DATA: self.__handle_data(byte_data)
        if action == tunnel_proto.ACT_DNS: self.send_message_to_handler(self.fileno, self.__dns_fd, byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.print_access_log("server_down")
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        if not self.__is_auth:
            self.print_access_log("not_get_server_response")
            self.dispatcher.ctunnel_fail()
            return
        self.__nat.recyle_ips()
        if not fnc_config.configs["udp_global"]: self.__udp_whitelist.recycle_cache()
        filter_ips = self.__timer.get_timeout_names()

        for ip in filter_ips:
            n = utils.ip4b_2_number(ip)
            fdsl_ctl.tf_record_del(self.__traffic_fetch_fd, n)
            if self.__timer.exists(ip): self.__timer.drop(ip)

        self.set_timeout(self.fileno, self.__TIMEOUT)
        # 尝试发送ping 5 次
        if self.__sent_ping_cnt < 5:
            self.__send_ping()
            return
        # 如果发送5次ping都没有响应,那么暂时取消会话
        self.__sent_ping_cnt = 0
        self.__handle_close()

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()
        self.dispatcher.ctunnel_fail()

        dels = []
        for k, v in self.__udp_proxy_map.items(): dels.append(v)
        for f in dels: self.delete_handler(f)

    @property
    def encrypt(self):
        return self.__encrypt_m

    @property
    def decrypt(self):
        return self.__decrypt_m

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
        uniq_id = self.get_id((saddr, sport,))

        fileno = 0
        if uniq_id not in self.__udp_proxy_map:
            fileno = self.create_handler(self.fileno, traffic_pass.udp_proxy,
                                         self.__traffic_send_fd, (saddr, sport,),
                                         uniq_id)
            self.__udp_proxy_map[uniq_id] = fileno
        else:
            fileno = self.__udp_proxy_map[uniq_id]
        self.send_message_to_handler(self.fileno, fileno, byte_data)

    def message_from_handler(self, from_fd, byte_data):
        # 处理来自local udp proxy的数据
        if from_fd != self.__traffic_fetch_fd:
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)
            return

        protocol = byte_data[9]
        # 处理UDP代理
        if protocol == 17 and not fnc_config.configs["udp_global"]:
            if self.__udp_whitelist.find(byte_data[16:20]):
                self.__udp_local_proxy_for_send(byte_data)
                return
            ''''''
        new_pkt = self.__nat.get_new_packet_to_tunnel(byte_data)
        if not new_pkt:
            self.print_access_log("can_not_send_to_tunnel")
            return

        dst_addr = new_pkt[16:20]
        self.__timer.set_timeout(dst_addr, self.__IP_TIMEOUT)
        pkt_len = (new_pkt[2] << 8) | new_pkt[3]
        self.send_data(pkt_len, new_pkt)

    def alloc_vlan_ips(self, ips):
        """分配虚拟IP地址"""
        if self.__debug: self.print_access_log("alloc_ip_list:%s" % str(ips))
        if len(ips) < 2:
            print("server not alloc enough ip")
            self.delete_handler(self.fileno)
            return
        self.__nat.add_virtual_ips(ips)

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__server
        echo = "%s        %s         %s" % (text, addr, t)

        print(echo)
        sys.stdout.flush()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("udp_nat_del", "request_dns",): return False
        if cmd == "request_dns":
            dns_msg, = args
            self.send_data(len(dns_msg), dns_msg, action=tunnel_proto.ACT_DNS)
            return True

        uniq_id, lan_address = args
        if uniq_id not in self.__udp_proxy_map: return
        del self.__udp_proxy_map[uniq_id]

    def fn_init(self):
        """初始化函数,重写这个方法"""
        pass

    def fn_auth_request(self):
        """重写这个方法,发送验证请求
        :return Bytes
        """
        pass

    def fn_auth_response(self, byte_data):
        """处理验证响应,重写这个方法
        :return Boolean: True表示验证成功,False表示验证失败
        """
        pass
