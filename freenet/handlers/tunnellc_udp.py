#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import fdslight_etc.fn_local as fnlc_config
import socket, sys, time
import freenet.lib.base_proto.tunnel_udp as tunnel_udp


class tunnellc_udp(udp_handler.udp_handler):
    __session_id = None
    __encrypt = None
    __decrypt = None

    __LOOP_TIMEOUT = 10

    __conn_time = 0
    __conn_timeout = 0

    def init_func(self, creator, session_id, is_ipv6=False):
        address = fnlc_config.configs["udp_server_address"]
        self.__conn_timeout = int(fnlc_config.configs["timeout"])

        name = "freenet.lib.crypto.%s" % fnlc_config.configs["udp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_config = fnlc_config.configs["udp_crypto_module"]["configs"]

        self.__encrypt = m.encrypt()
        self.__decrypt = m.decrypt()

        self.__encrypt.config(crypto_config)
        self.__decrypt.config(crypto_config)

        self.__session_id = session_id
        # 如果是域名,那么获取真是IP地址,防止死循环查询
        ipaddr = self.dispatcher.get_ipaddr(address[0])
        if not ipaddr: return -1

        if is_ipv6:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.set_socket(s)

        self.connect((ipaddr, address[1]))
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.dispatcher.tunnel_ok()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__conn_time = time.time()

        return self.fileno

    def __handle_ipv4_data_from_tunnel(self, byte_data):
        tun_fd = self.dispatcher.get_tun()
        self.send_message_to_handler(self.fileno, tun_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self, byte_data):
        pass

    def __send_data(self, byte_data, action=tunnel_udp.ACT_DATA):
        self.__conn_time = time.time()
        # if self.__debug: self.print_access_log("send_data")
        try:
            ippkts = self.__encrypt.build_packets(self.__session_id, action, byte_data)
            self.__encrypt.reset()
        except ValueError:
            return
        # print("send:", byte_data)
        for ippkt in ippkts: self.send(ippkt)

        self.add_evt_write(self.fileno)

    def __handle_data_from_tunnel(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        if ip_ver == 4: self.__handle_ipv4_data_from_tunnel(byte_data)
        if ip_ver == 6: self.__handle_ipv6_data_from_tunnel(byte_data)

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result
        if session_id != self.__session_id: return
        if action not in tunnel_udp.ACTS: return

        if action == tunnel_udp.ACT_DATA: self.__handle_data_from_tunnel(byte_data)
        if action == tunnel_udp.ACT_DNS:
            dns_fd = self.dispatcher.get_dns()
            self.ctl_handler(self.fileno, dns_fd, "response_dns", byte_data)
        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        if time.time() - self.__conn_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.dispatcher.tunnel_fail()
        self.close()

    def udp_error(self):
        self.delete_handler(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "request_dns": return
        message, = args
        self.__send_data(message, action=tunnel_udp.ACT_DNS)

    def __handle_ipv4_data_for_send(self, byte_data):
        daddr = byte_data[16:20]
        self.dispatcher.update_router_access_time(socket.inet_ntoa(daddr))
        self.__send_data(byte_data)

    def __handle_ipv6_data_for_send(self, byte_data):
        pass

    def message_from_handler(self, from_fd, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6): return
        if ip_ver == 4:
            self.__handle_ipv4_data_for_send(byte_data)
            return
        self.__handle_ipv6_data_for_send(byte_data)
