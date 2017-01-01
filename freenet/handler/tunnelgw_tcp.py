#!/usr/bin/env python3
import pywind.evtframework.handler.tcp_handler as tcp_handler
import fdslight_etc.fn_gw as fngw_config
import socket, time, sys
import freenet.handler.traffic_pass as traffic_pass
import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils


class tunnelc_tcp(tcp_handler.tcp_handler):
    __LOOP_TIMEOUT = 10

    __encrypt = None
    __decrypt = None

    __debug = None

    __traffic_fetch_fd = -1
    __traffic_send_fd = -1
    __traffic6_send_fd = -1

    __dns_fd = -1

    __BUFSIZE = 16 * 1024

    __session_id = None

    __wait_sent = None

    __conn_time = 0
    __conn_timeout = 0

    def init_func(self, creator_fd, session_id, dns_fd, raw_socket_fd, raw6_socket_fd, debug=False, is_ipv6=False):
        taddr = fngw_config.configs["tcp_server_address"]

        if is_ipv6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket()
        self.__wait_sent = []
        self.__session_id = session_id
        self.__conn_time = int(fngw_config.configs["timeout"])

        self.set_socket(s)
        self.dispatcher.bind_session_id(self.__session_id, self.fileno, "tcp")
        self.print_access_log("connect")
        self.connect(taddr, 6)

        crypto_info = fngw_config.configs["tcp_crypto_module"]
        name = crypto_info["name"]
        name = "freenet.lib.crypto.%s" % name

        __import__(name)
        m = sys.modules[name]

        self.__encrypt = m.encrypt()
        self.__decrypt = m.decrypt()

        self.__encrypt.config(crypto_info["configs"])
        self.__decrypt.config(crypto_info["configs"])

        self.__debug = debug
        self.__dns_fd = dns_fd
        self.__traffic_send_fd = raw_socket_fd
        self.__traffic6_send_fd = raw6_socket_fd

        return self.fileno

    def __send_data(self, sent_data, action=tunnel_tcp.ACT_DATA):
        self.__conn_time = time.time()
        sent_pkt = self.__encrypt.build_packet(self.__session_id, action, sent_data)
        # 丢弃阻塞的包
        if self.writer.size() > self.__BUFSIZE: self.writer.flush()
        self.__encrypt.reset()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)

    def connect_ok(self):
        # 可能目标主机不可达到
        try:
            n = utils.ip4s_2_number(self.getpeername()[0])
        except OSError:
            self.delete_handler(self.fileno)
            return

        self.__conn_time = time.time()
        self.print_access_log("connect_ok")

        if fngw_config.configs["udp_global"]:
            self.__traffic_fetch_fd = self.create_handler(self.fileno, traffic_pass.traffic_read)
            subnet, prefix = fngw_config.configs["udp_proxy_subnet"]
            subnet = utils.ip4b_2_number(socket.inet_aton(subnet))

            fdsl_ctl.set_udp_proxy_subnet(self.__traffic_fetch_fd, subnet, chr(int(prefix)).encode())
            fdsl_ctl.set_tunnel(self.__traffic_fetch_fd, n)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
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
        tun_fd = self.dispatcher.get_tun()
        self.send_message_to_handler(self.fileno, tun_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self, byte_data):
        pass

    def __handle_dns(self, dns_msg):
        self.send_message_to_handler(self.fileno, self.__dns_fd, dns_msg)

    def __handle_read(self, session_id, action, resp_data):
        if session_id != self.__session_id: return
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
            except proto_utils.ProtoError:
                self.print_access_log("wrong_format_packet")
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.__decrypt.get_pkt()
                if not pkt_info: break
                self.__handle_read(*pkt_info)
            ''''''
        return

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return
        if time.time() - self.__conn_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        self.print_access_log("disconnect")
        self.unregister(self.fileno)

        if self.is_conn_ok() and fngw_config.configs["udp_global"]:
            self.delete_handler(self.__traffic_fetch_fd)

        self.dispatcher.unbind_session_id(self.__session_id)
        self.close()

    def print_access_log(self, text):
        t = time.strftime("%Y-%m-%d %H:%M:%S")
        addr = "%s:%s" % fngw_config.configs["tcp_server_address"]
        echo = "%s        %s        %s" % (text, addr, t)
        print(echo)
        sys.stdout.flush()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("request_dns",): return
        if cmd == "request_dns":
            dns_msg, = args
            if not self.is_conn_ok():
                self.__wait_sent.append((1, dns_msg))
                return
            self.__send_dns(dns_msg)
        return

    def __handle_ipv4_traffic_from_lan(self, byte_data):
        size = len(byte_data)
        if size < 21: return

        protocol = byte_data[9]
        if protocol not in (1, 6, 17,): return

        ipaddr = socket.inet_ntoa(byte_data[16:20])
        self.dispatcher.update_router_access_time(ipaddr)
        self.__send_data(byte_data)

    def __handle_ipv6_traffic_from_lan(self, byte_data):
        pass

    def __handle_traffic_from_lan(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        if ip_ver == 4: self.__handle_ipv4_traffic_from_lan(byte_data)
        if ip_ver == 6: self.__handle_traffic_from_lan(byte_data)

    def message_from_handler(self, from_fd, byte_data):
        if not self.is_conn_ok():
            self.__wait_sent.append((0, byte_data), )
            return
        self.__handle_traffic_from_lan(byte_data)
