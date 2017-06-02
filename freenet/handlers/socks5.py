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

    __clients = None
    __clients_reverse = None

    __af = None
    __is_ipv6 = None

    def init_func(self, creator, cs, caddr, host_match, is_ipv6=False):
        self.__is_auth = False
        self.__is_connecting = False
        self.__caddr = caddr
        self.__is_connected = False
        self.__host_match = host_match
        self.__clients = {}
        self.__clients_reverse = {}

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
        if cmd == 1:
            name = "%s-%s" % (address, dport)
            fileno = self.create_handler(self.fileno, (address, dport,))

        self.__is_connecting = True

    def __send_data(self):
        pass

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
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("tell_delete"): return

        address, = args
        name = "%s-%s" % address

        if cmd == "tell_delete":

            if name not in self.__clients: return
            fileno, atyp, dst_address = self.__clients[name]

            del self.__clients[name]
            del self.__clients_reverse[fileno]

            return

        if cmd == "tell_connected":
            address, bind_address, = args
            if self.__is_ipv6:
                atyp = 1
            else:
                atyp = 4

            sent_data = socks5.build_response_and_udpdata(
                0, atyp,
                socket.inet_pton(self.__af, bind_address[0]), bind_address[1]
            )
            self.add_evt_write(self.fileno)
            self.writer.write(sent_data)
            return
        return

    def message_from_tunnel(self, c_ip, c_port, message):
        pass

    def message_from_handler(self, from_fd, message):
        pass


class sclient_tcp(tcp_handler.tcp_handler):
    __creator = None

    # 超时时间为20分钟
    __TIMEOUT = 1200

    __update_time = 0
    __address = None

    def init_func(self, creator, address, is_ipv6=False):
        self.__creator = creator
        self.__address = address

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

        ipaddr, port = self.socket.getsockname()

        self.ctl_handler(self.fileno, self.__creator, "tell_connected", (ipaddr, port,))

    def tcp_readable(self):
        self.set_timeout(self.fileno, 10)
        self.__update_time = time.time()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.ctl_handler(self.fileno, self.__creator, "tell_delete", self.__address)
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


class sclient_udp(udp_handler.udp_handler):
    pass
