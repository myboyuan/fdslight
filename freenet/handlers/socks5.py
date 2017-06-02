#!/usr/bin/env python3
"""socks5本地服务端实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import freenet.lib.socks5 as socks5
import freenet.lib.host_match as host_match
import socket, time


class sserverd(tcp_handler.tcp_handler):
    __host_match = None

    __is_ipv6 = None

    def init_func(self, creator, listen, listen_ipv6=False):
        if listen_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        s = socket.socket(af, socket.SOCK_STREAM)

        if listen_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.__is_ipv6 = listen_ipv6

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(listen)

        self.__host_match = host_match.host_match()

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(
                    self.fileno, _sserverd_handler,
                    cs, address, self.__host_match, is_ipv6=self.__is_ipv6
                )
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def set_host_rules(self, rules):
        self.__host_match.clear()
        for rule in rules: self.__host_match.add_rule(rule)


class _sserverd_handler(tcp_handler.tcp_handler):
    __is_auth = None
    __is_connecting = None
    __is_connected = False

    __caddr = None
    __host_match = None

    __is_ipv6 = None

    __fileno = None

    __delete_flags = None

    def init_func(self, creator, cs, caddr, host_match, is_ipv6=False):
        self.__is_auth = False
        self.__is_connecting = False
        self.__caddr = caddr
        self.__is_connected = False
        self.__host_match = host_match
        self.__delete_flags = False

        if is_ipv6:
            self.__af = socket.AF_INET6
        else:
            self.__af = socket.AF_INET

        self.__is_ipv6 = is_ipv6

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def __do_auth(self):
        byte_data = self.reader.read()
        methods = socks5.parse_handshake_request(byte_data)
        no_auth_method = False

        for m in methods:
            if m == 0:
                no_auth_method = True
                break
        # 只支持不验证方法
        if not no_auth_method:
            self.delete_handler(self.fileno)
            return
        resp_data = socks5.build_handshake_response(0)

        self.add_evt_write(self.fileno)
        self.writer.write(resp_data)
        self.__is_auth = True

    def __do_connect(self):
        read_data = self.reader.read()

        try:
            cmd, atyp, fragment, address, dport, data = socks5.parse_request_and_udpdata(read_data)
        except socks5.ProtocolErr:
            self.delete_handler(self.fileno)
            return

        if atyp == 3:
            is_match, flags = self.__host_match.match(address)
            if is_match: return

        if atyp == 4:
            is_ipv6 = True
        else:
            is_ipv6 = self.__is_ipv6

        if cmd == 1:
            self.__fileno = self.create_handler(self.fileno, sclient_tcp, (address, dport,), is_ipv6=is_ipv6)
        self.__is_connecting = True

    def __send_data(self):
        read_data = self.reader.read()
        self.send_message_to_handler(self.fileno, self.__fileno, read_data)

    def tcp_readable(self):
        if not self.__is_auth:
            self.__do_auth()
            return
        if not self.__is_connecting:
            self.__do_connect()
            return
        if not self.__is_connected: return

        self.__send_data()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        if self.handler_exists(self.__fileno) and not self.__delete_flags:
            self.__delete_flags = True
            self.delete_handler(self.__fileno)
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "tell_connected":
            address, = args
            self.__is_connected = True

            if self.__is_ipv6:
                atyp = 4
            else:
                atyp = 1

            sent_data = socks5.build_response_and_udpdata(
                0, atyp, address[0], address[1]
            )
            self.add_evt_write(self.fileno)
            self.writer.write(sent_data)

        return True

    def message_from_proxy(self, message):
        self.add_evt_write(self.fileno)
        self.writer.write(message)


class sclient_tcp(tcp_handler.tcp_handler):
    __creator = None

    # 超时时间为15分钟
    __TIMEOUT = 900

    __update_time = 0
    __address = None

    __sclient_address = None

    # 连接成功之后的回调函数
    __connected_callback = None

    # 数据接收函数
    __recv_callback = None

    def init_func(self, creator, connected_callback, recv_callback, sclient_address, address, is_ipv6=False):
        self.__creator = creator
        self.__address = address
        self.__sclient_address = sclient_address
        self.__connected_callback = connected_callback
        self.__recv_callback = recv_callback

        if is_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        s = socket.socket(af, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__update_time = time.time()

        address = self.socket.getsockname()

        self.__connected_callback(self.fileno, self.__sclient_address, address)

    def tcp_readable(self):
        self.set_timeout(self.fileno, 10)
        self.__update_time = time.time()

        read_data = self.reader.read()
        self.send_message_to_handler(self.fileno, self.__creator, read_data)

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if self.is_conn_ok() and t - self.__update_time < self.__TIMEOUT:
            self.set_timeout(self.fileno, 10)
            return
        self.delete_handler(self.fileno)

    def send_message(self, message):
        self.writer.write(message)
        self.add_evt_write(self.fileno)


class sclient_udp(udp_handler.udp_handler):
    pass
