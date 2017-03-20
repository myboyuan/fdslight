#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket, time


class tcp_tunnel(tcp_handler.tcp_handler):
    __crypto = None
    __crypto_configs = None
    __conn_timeout = None

    def init_func(self, creator, address, crypto, crypto_configs, conn_timeout=800, is_ipv6=False):
        self.__crypto_configs = crypto_configs
        self.__crypto = crypto
        self.__conn_timeout = conn_timeout

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(
                    self.fileno, self.__crypto,
                    self.__crypto_configs, cs, address, self.__conn_timeout
                )
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _tcp_tunnel_handler(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None
    __address = None

    __update_time = 0
    __conn_timeout = 0

    __LOOP_TIMEOUT = 10

    def init_func(self, creator, crypto, crypto_configs, cs, address, conn_timeout):
        self.__address = address
        self.__conn_timeout = conn_timeout
        self.__update_time = time.time()

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        return self.fileno

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        self.remove_evt_read(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class udp_tunnel(udp_handler.udp_handler):
    def init_func(self, creator, address, crypto, crypto_configs, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        return self.fileno

    def udp_readable(self, message, address):
        pass

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
