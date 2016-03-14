#!/usr/bin/env python3
"""
隧道客户端基本类
"""
import json, socket, sys, time
import fdslight_etc.fn_client as fnc_config
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import freenet.lib.checksum as checksum
import freenet.lib.base_proto.tunnel as tunnel_proto
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.handler.dns_proxy as dns_proxy


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
        self.__timer.set_timeout(dst_addr, self.__IP_TIMEOUT)
        pkt_list = list(pkt)
        checksum.modify_address(dst_lan, pkt_list, checksum.FLAG_MODIFY_DST_IP)

        return bytes(pkt_list)

    def recyle_ips(self):
        """回收已经分配出去的IP地址"""
        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__dst_nat_table:
                t = self.__dst_nat_table[name]
                # 重新加入到待分配的列表中
                self.__virtual_ips.append(name)

                del self.__dst_nat_table[name]
                del self.__src_nat_table[t]
            if self.__timer.exists(name): self.__timer.drop(name)
        return

    def reset(self):
        self.__virtual_ips = []
        self.__dst_nat_table = {}
        self.__src_nat_table = {}


class tunnelc_base(udp_handler.udp_handler):
    __nat = None
    __server = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -2
    __dns_fd = -1

    __encrypt_m = None
    __decrypt_m = None

    __TIMEOUT = 45
    __TIMEOUT_NO_AUTH = 5
    __session_id = 0

    # DNS server的网络序地址
    __dns_server_addrn = None
    __is_auth = False

    # 发送ping的次数
    __sent_ping_cnt = 0

    # 是否曾经打开过流量捕获设备
    __is_open_fetch_fd_once = False
    __whitelist = None

    __debug = False

    # 服务端IP地址
    __server_ipaddr = None
    # send auth次数
    __sent_auth_cnt = 0

    def init_func(self, creator_fd, whitelist, blacklist, debug=False):
        self.__nat = _static_nat()
        self.__server = fnc_config.configs["server_address"]

        name = "freenet.lib.crypto.%s" % fnc_config.configs["crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_args = fnc_config.configs["crypto_module"].get("args", ())
        self.__encrypt_m = m.encrypt(*crypto_args)
        self.__decrypt_m = m.decrypt(*crypto_args)

        self.__debug = debug

        self.__traffic_send_fd = self.create_handler(self.fileno, traffic_pass.traffic_send)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.__dns_fd = self.create_handler(self.fileno, dns_proxy.dns_proxy, blacklist, debug=debug)

        self.connect(self.__server)

        ipaddr, _ = s.getpeername()

        self.__server_ipaddr = ipaddr
        self.__dns_server_addrn = socket.inet_aton(fnc_config.configs["dns_encrypt"])

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.fn_init()
        self.fn_auth_request()
        self.__whitelist = whitelist
        self.set_timeout(self.fileno, self.__TIMEOUT_NO_AUTH)

        return self.fileno

    def __handle_data(self, byte_data):
        p = byte_data[9]

        # 过滤到不支持的协议
        if p not in (1, 6, 17,): return

        new_pkt = self.__nat.get_new_packet_for_lan(byte_data)
        if not new_pkt:
            self.print_access_log("cant_not_send_packet_to_lan")
            return

        self.set_timeout(self.fileno, self.__TIMEOUT)

        if p != 17:
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, new_pkt)
            return

        # 需要特殊对待DNS的UDP数据包
        src_addr = new_pkt[12:16]
        if src_addr != self.__dns_server_addrn:
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, new_pkt)
            return

        ihl = (new_pkt[0] & 0x0f) * 4
        b = ihl
        e = ihl + 1
        sport = (new_pkt[b] << 8) | new_pkt[e]

        if sport != 53:
            self.send_message_to_handler(self.fileno, self.__traffic_send_fd, new_pkt)
            return

        self.send_message_to_handler(self.fileno, self.__dns_fd, new_pkt)

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
        if self.__is_open_fetch_fd_once:
            whitelist = []
        else:
            whitelist = self.__whitelist

        self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read, whitelist)

        n = utils.ip4s_2_number(self.__server_ipaddr)
        fdsl_ctl.add_whitelist_subnet(self.__traffic_fetch_fd, n, 32)

        self.__is_auth = True
        self.__sent_auth_cnt = 0
        self.ctl_handler(self.fileno, self.__dns_fd, "tunnel_open")
        self.ctl_handler(self.fileno, self.__dns_fd, "set_filter_dev_fd", self.__traffic_fetch_fd)
        self.set_timeout(self.fileno, self.__TIMEOUT)

    def set_session_id(self, sid):
        self.encrypt.set_session_id(sid)

    def send_data(self, pkt_len, byte_data, action=tunnel_proto.ACT_DATA):
        ippkts = self.__encrypt_m.build_packets(action, pkt_len, byte_data)
        self.__encrypt_m.reset()

        for ippkt in ippkts:
            self.send(ippkt)

        if self.__is_auth: self.set_timeout(self.fileno, self.__TIMEOUT)

        self.add_evt_write(self.fileno)

    def send_auth(self, auth_data):
        self.__sent_auth_cnt += 1
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
            self.print_access_log("received_ping")
            self.__send_pong()
        if action == tunnel_proto.ACT_PONG:
            self.print_access_log("received_pong")
            self.__sent_ping_cnt = 0
        if action == tunnel_proto.ACT_DATA: self.__handle_data(byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.print_access_log("server_down")
        sys.exit(-1)

    def udp_timeout(self):
        self.__nat.recyle_ips()

        if not self.__is_auth:
            if self.__sent_auth_cnt > 5:
                self.error()
                return
            self.set_timeout(self.fileno, self.__TIMEOUT_NO_AUTH)
            self.fn_auth_request()
            return

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
        sys.exit(-1)

    @property
    def encrypt(self):
        return self.__encrypt_m

    @property
    def decrypt(self):
        return self.__decrypt_m

    def message_from_handler(self, from_fd, byte_data):
        if from_fd == self.__dns_fd:
            if not self.__is_auth:
                self.send_message_to_handler(self.fileno, self.__traffic_send_fd, byte_data)
                return

        new_pkt = self.__nat.get_new_packet_to_tunnel(byte_data)
        if not new_pkt: return

        pkt_len = (new_pkt[2] << 8) | new_pkt[3]
        self.send_data(pkt_len, new_pkt)

    def alloc_vlan_ips(self, ips):
        """分配虚拟IP地址"""
        self.__nat.add_virtual_ips(ips)

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % self.__server
        echo = "%s        %s         %s" % (text, addr, t)

        print(echo)

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
