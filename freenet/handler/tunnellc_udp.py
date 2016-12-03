#!/usr/bin/env python3
import pywind.evtframework.handler.udp_handler as udp_handler
import fdslight_etc.fn_local as fnlc_config
import socket, sys
import freenet.lib.base_proto.tunnel_udp as tunnel_udp


class tunnellc_udp(udp_handler.udp_handler):
    __session_id = None
    __encrypt = None
    __decrypt = None

    __tun_fd = -1
    __LOOP_TIMEOUT = 10

    def init_func(self, creator, session_id,is_ipv6=False):
        address = fnlc_config.configs["udp_server_address"]

        name = "freenet.lib.crypto.%s" % fnlc_config.configs["udp_crypto_module"]["name"]
        __import__(name)
        m = sys.modules.get(name, None)

        crypto_config = fnlc_config.configs["udp_crypto_module"]["configs"]

        self.__encrypt_m = m.encrypt()
        self.__decrypt_m = m.decrypt()

        self.__encrypt_m.config(crypto_config)
        self.__decrypt_m.config(crypto_config)

        self.__tun_fd = tun_fd

        if is_ipv6:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET

        s = socket.socket(family, socket.SOCK_DGRAM)
        self.set_timeout(s)

        try:
            self.connect(address)
        except socket.gaierror:
            self.delete_handler(self.fileno)

        self.dispatcher.tunnel_ok()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def __handle_ipv4_data_from_tunnel(self, byte_data):
        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def __handle_ipv6_data_from_tunnel(self, byte_data):
        pass

    def __handle_data_from_tunnel(self, byte_data):
        ip_ver = (byte_data[0] & 0xf0) >> 4
        if ip_ver not in (4, 6,): return
        if ip_ver == 4: self.__handle_ipv4_data_from_tunnel(byte_data)
        if ip_ver == 6: self.__handle_ipv6_data_from_tunnel(byte_data)

    def udp_readable(self, message, address):
        result = self.__decrypt_m.parse(message)
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
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.dispatcher.tunnel_fail()
        self.close()

    def udp_error(self):
        self.delete_handler(self.fileno)
