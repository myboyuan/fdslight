#!/usr/bin/env python3


import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import time, socket


class tcp_proxy(tcp_handler.tcp_handler):
    __TIMEOUT = 600
    __update_time = 0
    __cookie_id = None
    __session_id = None
    __debug = None

    def init_func(self, creator, session_id, cookie_id, address, is_ipv6=False, debug=True):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__cookie_id = cookie_id
        self.__session_id = session_id

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.__cookie_id = cookie_id
        self.__debug = debug

        if self.__debug: print(address)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.dispatcher.response_socks_connstate(self.__session_id, self.__cookie_id, 2)
        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)

        if self.__debug: print("connect ok")

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        if not self.writer.is_empty(): self.add_evt_write(self.fileno)

    def tcp_delete(self):
        if self.__debug: print("tcp_app_proxy delete")

        if self.is_conn_ok():
            self.dispatcher.response_socks_close(self.__session_id, self.__cookie_id)
        else:
            self.dispatcher.response_socks_connstate(self.__session_id, self.__cookie_id, 0)

        self.dispatcher.tell_del_app_proxy(self.__session_id, self.__cookie_id)
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        if self.is_conn_ok():
            rdata = self.reader.read()
            print(rdata)
            self.dispatcher.response_socks_tcp_data(self.__session_id, self.__cookie_id, rdata)
        if self.__debug: print("tcp_app_proxy error")
        self.delete_handler(self.fileno)

    def tcp_readable(self):
        self.__update_time = time.time()
        rdata = self.reader.read()

        self.dispatcher.response_socks_tcp_data(self.__session_id, self.__cookie_id, rdata)

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            if self.__debug: print("tcp_app_proxy cannot connect")
            self.dispatcher.response_socks_connstate(self.__session_id, self.__cookie_id, 0)
            self.delete_handler(self.fileno)
            return
        t = time.time() - self.__update_time

        if t > self.__TIMEOUT:
            if self.__debug: print("tcp_app_proxy timeout")
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def handle_data_from_client(self, message):
        self.writer.write(message)

        if not self.is_conn_ok(): return

        self.__update_time = time.time()
        self.add_evt_write(self.fileno)


class udp_proxy(udp_handler.udp_handler):
    __cookie_id = None
    __session_id = None
    __permits = None

    __is_ipv6 = None
    __update_time = 0
    __TIMEOUT = 180

    def init_func(self, creator, session_id, cookie_id, bind_ip=None, is_ipv6=False, debug=True):
        if is_ipv6:
            fa = socket.AF_INET6
            if not bind_ip: bind_ip = "::"
        else:
            fa = socket.AF_INET
            if not bind_ip: bind_ip = "0.0.0.0"

        self.__cookie_id = cookie_id
        self.__session_id = session_id
        self.__permits = {}
        self.__is_ipv6 = is_ipv6

        s = socket.socket(fa, socket.SOCK_DGRAM)
        self.set_socket(s)
        self.bind((bind_ip, 0))

        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)
        self.dispatcher.response_socks_connstate(self.__session_id, self.__cookie_id, 2)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        # 进行端口限制
        if address[1] not in self.__permits: return

        self.dispatcher.response_socks_udp_data(
            self.__session_id, self.__cookie_id,
            address[0], address[1], message, is_ipv6=self.__is_ipv6
        )

    def handle_data_from_client(self, is_ipv6, host, port, message):
        if is_ipv6 != self.__is_ipv6: return

        self.__update_time = time.time()
        self.__permits[port] = None
        self.sendto(message, (host, port,))
        self.add_evt_write(self.fileno)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        t = time.time() - self.__update_time

        if t > self.__TIMEOUT:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.response_socks_close(self.__session_id, self.__cookie_id)
        self.dispatcher.tell_del_app_proxy(self.__session_id, self.__cookie_id)
        self.unregister(self.fileno)
        self.close()
