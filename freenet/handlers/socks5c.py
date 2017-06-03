#!/usr/bin/env python3
"""socks5本地服务端实现
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
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

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

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

    def init_func(self, creator, cs, caddr, host_match, udp_global_subnet):
        self.__host_match = host_match
        self.__udp_global_subnet = udp_global_subnet
        self.__conn_is_ipv6 = False
        self.__proxy_client_fileno = -1

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
        pass

    def __send_data_from_local(self):
        pass

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
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "tell_delete":
            self.delete_handler(self.fileno)
            return True

        if cmd == "tell_connect_ok":
            pass

        return False

    def __send_data_to_local(self, message):
        self.writer.write(message)
        self.add_evt_write(self.fileno)

    def message_from_handler(self, from_fd, message):
        self.__send_data_to_local(message)

    def message_from_tunnel(self, message):
        self.__send_data_to_local(message)


class sclient_tcp(tcp_handler.tcp_handler):
    __creator = None

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

        self.ctl_handler(self.fileno, self.__creator, "tell_connect_ok", addrinfo)

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
        return
