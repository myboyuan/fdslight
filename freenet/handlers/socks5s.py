#!/usr/bin/env python3
"""socks5服务端代理实现
"""
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import freenet.lib.socks5 as socks5
import socket, time


class sclient_tcp(tcp_handler.tcp_handler):
    __TIMEOUT = 720
    __update_time = 0
    __conn_id = None
    __atyp = None
    __address = None

    __session_id = None
    __connid = None

    def init_func(self, creator, session_id, connid, atyp, address, is_ipv6=False):
        self.__atyp = atyp
        self.__address = address
        self.__session_id = session_id
        self.__conn_id = connid

        if is_ipv6:
            af = socket.AF_INET
        else:
            af = socket.AF_INET6

        s = socket.socket(af, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)

        sent_data = socks5.build_response_and_udpdata(0, self.__atyp, self.__address[0], self.__address[1])
        self.dispatcher.send_socks5_msg_to_tunnel(self.__session_id, self.__conn_id, sent_data)

    def tcp_readable(self):
        self.dispatcher.send_socks5_msg_to_tunnel()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_del_socks5_proxy(self.__session_id, self.__conn_id)
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            sent_data = socks5.build_response_and_udpdata(5, self.__atyp, self.__address[0], self.__address[1])
            self.dispatcher.send_socks5_msg_to_tunnel(self.__session_id, self.__conn_id, sent_data)
            self.delete_handler(self.fileno)
            return

        t = time.time()
        if t - self.__update_time > self.__TIMEOUT:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)

    def message_from_tunnel(self, message):
        self.__update_time = time.time()
        self.writer.write(message)
        self.add_evt_write(self.fileno)


class sclient_udp(udp_handler.udp_handler):
    __session_id = None
    __connid = None

    # 允许的客户端
    __permits = None

    __update_time = 0
    __TIMEOUT = 180

    __atyp = 0

    def init_func(self, creator, session_id, connid, is_ipv6=False):
        self.__session_id = session_id
        self.__connid = connid
        self.__permits = {}

        if is_ipv6:
            af = socket.AF_INET6
            bindaddr = ("::", 0)
            self.__atyp = 4
        else:
            af = socket.AF_INET
            bindaddr = ("0.0.0.0", 0)
            self.__atyp = 1

        s = socket.socket(af, socket.SOCK_DGRAM)
        self.set_socket(s)
        self.bind(bindaddr)

        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def message_from_tunnel(self, message):
        try:
            cmd, fragment, atyp, sts_address, dport, data = socks5.parse_request_and_udpdata(
                message, is_udp=True
            )
        except socks5.ProtocolErr:
            return

        # 暂时不支持分包
        if fragment != 0: return
        if fragment == 0 and dport == 0: return

        self.__permits[dport] = None
        self.__update_time = time.time()

        self.add_evt_write(self.fileno)
        self.sendto(data, (sts_address, dport,))

    def udp_delete(self):
        self.dispatcher.tell_del_socks5_proxy(self.__session_id, self.__connid)
        self.unregister(self.fileno)
        self.close()

    def udp_readable(self, message, address):
        if address[1] not in self.__permits: return

        sent_data = socks5.build_response_and_udpdata(
            0, self.__atyp, address[0], address[1], udp_data=message
        )
        self.dispatcher.send_socks5_msg_to_tunnel(
            self.__session_id, self.__connid, sent_data, is_udp=True
        )

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__TIMEOUT:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)
