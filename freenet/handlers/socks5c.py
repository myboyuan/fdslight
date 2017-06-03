#!/usr/bin/env python3
"""socks5本地代理实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import freenet.lib.utils as utils
import freenet.lib.host_match as host_match
import freenet.lib.socks5 as socks5
import socket, time


class sserverd(tcp_handler.tcp_handler):
    __host_match = None
    __udp_global_subnet = None

    def init_func(self, creator, listen, udp_global_subnet, listen_ipv6=False):
        self.__host_match = host_match.host_match()
        self.__udp_global_subnet = udp_global_subnet

        if listen_ipv6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        s = socket.socket(af, socket.SOCK_STREAM)

        if listen_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(listen)

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
                    cs, address, self.__host_match, self.__udp_global_subnet
                )
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _sserverd_handler(tcp_handler.tcp_handler):
    __host_match = None
    __udp_global_subnet = None

    __is_auth = None
    __is_connecting = None
    __is_connected = None

    __conn_is_ipv6 = None

    __proxy_client_fileno = None

    __atyp = 0

    # 数据包是否要发送到隧道
    __is_sent_to_tunnel = False

    def init_func(self, creator, cs, caddr, host_match, udp_global_subnet):
        self.__host_match = host_match
        self.__udp_global_subnet = udp_global_subnet
        self.__conn_is_ipv6 = False
        self.__proxy_client_fileno = -1
        self.__is_sent_to_tunnel = False

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def __do_auth(self):
        rdata = self.reader.read()
        try:
            methods = socks5.parse_handshake_request(rdata)
        except socks5.ProtocolErr:
            self.delete_handler(self.fileno)
            return

        is_no_auth = False

        for m in methods:
            if m == 0:
                is_no_auth = True
                break
            ''''''
        if not is_no_auth:
            self.delete_handler(self.fileno)
            return
        sent_data = socks5.build_handshake_response(0)
        self.__send_data_to_local(sent_data)
        self.__is_auth = True

    def __do_connecting(self):
        rdata = self.reader.read()
        try:
            cmd, fragment, atyp, sts_address, dport, data = socks5.parse_request_and_udpdata(rdata, is_udp=False)
        except socks5.ProtocolErr:
            self.delete_handler(self.fileno)
            return

        # 去除BIND支持,bind已经很少使用
        if cmd not in (1, 3,):
            self.delete_handler(self.fileno)
            return

        self.__is_connecting = True
        if cmd == 1:
            self.__handle_tcp_connect(atyp, sts_address, dport, rdata)
        if cmd == 3:
            self.__handle_udp_connect(atyp, self.getpeername()[0], dport, rdata)
        return

    def __handle_udp_connect(self, atyp, address, port, message):
        if port == 0:
            self.delete_handler(self.fileno)
            return

        if atyp == 4:
            is_ipv6 = True
        else:
            is_ipv6 = False

        if utils.check_is_from_subnet(address, self.__udp_global_subnet[0], self.__udp_global_subnet[1]):
            forward_to_tunnel = True
        else:
            forward_to_tunnel = False

        self.__proxy_client_fileno = self.create_handler(
            self.fileno, sclient_udp,
            (address, port,), is_ipv6=is_ipv6,
            forward_to_tunnel=forward_to_tunnel
        )

    def __handle_tcp_connect(self, atyp, address, port, message):
        """
        :param atyp:
        :param address:
        :param port:
        :param message:从客户端接收的原始消息
        :return:
        """
        if port == 0:
            self.delete_handler(self.fileno)
            return
        if atyp == 3:
            is_match, flags = self.__host_match.match(address)

            # 只处理标志为1的规则
            if is_match and flags == 1:
                self.__is_sent_to_tunnel = True
                self.__is_connecting = True
                self.dispatcher.send_socks5_msg_to_tunnel(self.fileno, message)
                return

        if atyp == 4:
            is_ipv6 = True
        else:
            is_ipv6 = False

        self.__conn_is_ipv6 = is_ipv6
        self.__atyp = atyp

        self.__proxy_client_fileno = self.create_handler(
            self.fileno, sclient_tcp, (address, port,), is_ipv6=is_ipv6
        )

    def __send_data_from_local(self):
        rdata = self.reader.read()

        if self.__is_sent_to_tunnel:
            self.dispatcher.send_socks5_msg_to_tunnel(self.fileno, rdata)
            return

        if not self.handler_exists(self.__proxy_client_fileno):
            self.delete_handler(self.fileno)
            return

        self.send_message_to_handler(self.fileno, self.__proxy_client_fileno, rdata)

    def tcp_readable(self):
        if not self.__is_auth:
            self.__do_auth()
            return

        if not self.__is_connecting:
            self.__do_connecting()
            return
        # 在没有验证完成就发送数据包那么直接断开连接
        if not self.__is_connected:
            self.delete_handler(self.fileno)
            return

        self.__send_data_from_local()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        if self.handler_exists(self.__proxy_client_fileno):
            self.delete_handler(self.__proxy_client_fileno)

        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "tell_delete":
            self.delete_handler(self.fileno)
            return True

        if cmd == "tell_connect_ok":
            address, = args
            sent_data = socks5.build_response_and_udpdata(0, self.__atyp, address[0], address[1])
            self.__send_data_to_local(sent_data)
            self.__is_connected = True
            return True

        return False

    def __send_data_to_local(self, message):
        self.writer.write(message)
        self.add_evt_write(self.fileno)

    def message_from_handler(self, from_fd, message):
        self.__send_data_to_local(message)

    def message_from_tunnel(self, message):
        if not self.__is_connected:
            if message[1] != 0:
                self.delete_handler(self.fileno)
                return
            self.__is_connected = True
        self.__send_data_to_local(message)


class sclient_tcp(tcp_handler.tcp_handler):
    __creator = None

    __TIMEOUT = 900
    __update_time = 0

    def init_func(self, creator, address, is_ipv6=False):
        self.__creator = creator

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

        addrinfo = self.socket.getsockname()

        self.__update_time = time.time()

        self.ctl_handler(self.fileno, self.__creator, "tell_connect_ok", addrinfo)
        self.set_timeout(self.fileno, 10)

    def tcp_readable(self):
        rdata = self.reader.read()

        self.__update_time = time.time()
        self.send_message_to_handler(self.fileno, self.__creator, rdata)

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.ctl_handler(self.fileno, self.__creator, "tell_delete")

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.ctl_handler(self.fileno, self.__creator, "tell_delete")
            return

        t = time.time()
        if t - self.__update_time > self.__TIMEOUT:
            self.ctl_handler(self.fileno, self.__creator, "tell_delete")
            return

        self.set_timeout(self.fileno, 10)

    def message_from_handler(self, from_fd, message):
        self.writer.write(message)
        self.add_evt_write(self.fileno)


class sclient_udp(udp_handler.udp_handler):
    __addrinfo = None
    __creator = None
    __forward_to_tunnel = None
    __is_ipv6 = None
    __client_address = None

    # 允许收到的数据包
    __permits = None

    __TIMEOUT = 180
    __update_time = 0

    def init_func(self, creator, client_address, is_ipv6=False, forward_to_tunnel=False):
        """
        :param creator:
        :param forward_to_tunnel: 是否吧数据转发到隧道
        :return:
        """
        self.__creator = creator
        self.__forward_to_tunnel = forward_to_tunnel
        self.__is_ipv6 = is_ipv6
        self.__client_address = client_address
        self.__permits = {}

        if is_ipv6:
            af = socket.AF_INET6
            bindaddr = ("::", 0)
        else:
            af = socket.AF_INET
            bindaddr = ("0.0.0.0", 0)

        s = socket.socket(af, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.bind(bindaddr)

        addrinfo = self.getsockname()
        self.__addrinfo = addrinfo

        self.ctl_handler(self.fileno, self.__creator, "tell_connect_ok", addrinfo)
        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        # 处理客户端发送过来的数据包

        # 如果与协商的端口不一致,那么丢弃数据包
        if address[0] == self.__client_address and address[1] != self.__client_address[1]:
            return

        if address[0] == self.__client_address[0]:
            self.__client_port = address[1]
            try:
                cmd, fragment, atyp, sts_address, dport, data = socks5.parse_request_and_udpdata(message, is_udp=True)
            except socks5.ProtocolErr:
                return

            # 暂不支持分包
            if fragment != 0: return
            if dport == 0: return

            self.__permits[dport] = None
            if self.__forward_to_tunnel:
                self.dispatcher.send_socks5_msg_to_tunnel(self.fileno, message)
                return
            return
        if address[1] not in self.__permits: return

        self.__update_time = time.time()
        self.__send_message_from_local(message, address)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_error(self):
        self.ctl_handler(self.fileno, self.__creator, "tell_delete")

    def message_from_tunnel(self, message):
        try:
            cmd, fragment, atyp, sts_address, dport, data = socks5.parse_request_and_udpdata(message, is_udp=True)
        except socks5.ProtocolErr:
            return
        self.__update_time = time.time()
        self.sendto(message, (sts_address, dport))

    def __send_message_from_local(self, message, address):
        self.add_evt_write(self.fileno)
        self.sendto(message, address)

    def udp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__TIMEOUT:
            self.ctl_handler(self.fileno, self.__creator, "tell_delete")
            return
        self.set_timeout(self.fileno, 10)
