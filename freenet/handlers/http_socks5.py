#!/usr/bin/env python3
"""HTTP socks5代理
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time, struct
import freenet.lib.host_match as host_match
import pywind.web.lib.httputils as httputils


class http_socks5_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, address, host_rules, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_readable(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                self.create_handler(self.fileno, cs, caddr)
        return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _http_socks5_handler(tcp_handler.tcp_handler):
    __caddr = None
    __is_udp = None
    __fileno = None
    __step = 0

    # 是否是HTTP代理
    __is_http = None

    __is_ipv6 = None

    __use_tunnel = None

    def init_func(self, creator, cs, caddr, host_rules):
        self.set_socket(cs)
        self.__is_udp = False
        self.__caddr = caddr
        self.__fileno = -1
        self.__step = 1
        self.__is_http = False
        self.__is_ipv6 = False
        self.__use_tunnel = False

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def __handle_socks5_step1(self):
        pass

    def __handle_socks5_step2(self):
        size = self.reader.size()

        if size < 7:
            self.delete_handler(self.fileno)
            return

        ver, cmd, rsv, atyp = struct.unpack("!bbbb", self.reader.read(4))

        if ver != 5:
            self.delete_handler(self.fileno)
            return

        # 只支持connect与udp
        if cmd not in (1, 3,):
            self.delete_handler(self.fileno)
            return

        if atyp not in (1, 3, 4,):
            self.delete_handler(self.fileno)
            return

        size = self.reader.size()

        if atyp == 1:
            if size < 7:
                self.delete_handler(self.fileno)
                return
            addr = socket.inet_ntop(socket.AF_INET, self.reader.read(4))
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, self.reader.read(16))
        else:
            addr_len = self.reader.read(1)[0]
            size = self.reader.size()
            if size < addr_len:
                self.delete_handler(self.fileno)
                return
            addr = self.reader.read(addr_len).decode("iso-8859-1")

        byte_port = self.reader.read(2)
        port = (byte_port[0] << 8) | byte_port[1]

    def __handle_socks5_step3(self):
        rdata = self.reader.read()
        self.send_message_to_handler(self.fileno, self.__fileno, rdata)

    def __handle_http_step1(self):
        pass

    def __handle_http_step2(self):
        pass

    def __handle_http_step3(self):
        pass

    def __handle_http(self):
        if self.__step == 1:
            self.__handle_http_step1()
            return

        if self.__step == 2:
            self.__handle_http_step2()
            return

        self.__handle_http_step3()

    def __handle_socks5(self):
        if self.__step == 1:
            self.__handle_socks5_step1()
            return

        if self.__step == 2:
            self.__handle_socks5_step2()
            return

        self.__handle_socks5_step3()

    def hander_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in ("tell_ok", "tell_error", "tell_close"): return

        if cmd == "tell_close":
            self.delete_this_no_sent_data()
            return

        if cmd == "tell_ok":
            rep = 0
        else:
            rep = 5

        addr, port = args
        if self.__is_ipv6:
            atyp = 4
            addr_len = 16
            byte_ip = socket.inet_pton(socket.AF_INET6, addr)
        else:
            atyp = 1
            addr_len = 4
            byte_ip = socket.inet_pton(socket.AF_INET, addr)

        fmt = "!bbbb%ssH" % addr_len
        sent_data = struct.pack(
            fmt, 5, rep, 0, atyp, byte_ip, port
        )

        self.__send_data(sent_data)

        if cmd == "tell_ok":
            self.__step = 3
            return

        if cmd == "tell_error":
            self.delete_this_no_sent_data()
            return

    def tcp_readable(self):
        if not self.__is_http:
            self.__handle_socks5()
        else:
            self.__handle_http()
        return

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_delete(self):
        if self.handler_exists(self.__fileno):
            self.delete_handler(self.__fileno)
        self.unregister(self.fileno)
        self.close()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def __send_data(self, message):
        self.add_evt_write(self.fileno)
        self.writer.write(message)


class _tcp_client(tcp_handler.tcp_handler):
    __TIMEOUT = 300
    __update_time = 0
    __creator = None

    def init_func(self, creator, address, host_rules, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.__creator = creator
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.__update_time = time.time()
        self.set_timeout(self.fileno, 10)

        address, port = self.socket.getsockname()

        self.ctl_handler(
            self.fileno, self.__creator,
            "tell_ok", address, port
        )

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            address, port = self.socket.getsockname()
            self.ctl_handler(
                self.fileno, self.__creator,
                "tell_error", address, port
            )
            return
        t = time.time() - self.__update_time
        if t > self.__TIMEOUT:
            self.ctl_handler(
                self.fileno, self.__creator,
                "tell_close"
            )
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        if self.is_conn_ok():
            self.ctl_handler(
                self.fileno, self.__creator,
                "tell_close"
            )
        else:
            address, port = self.socket.getsockname()
            self.ctl_handler(
                self.fileno, self.__creator,
                "tell_error", address, port
            )
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, message):
        self.writer.write(message)
        self.add_evt_write(self.fileno)


class _udp_handler(udp_handler.udp_handler):
    __TIMEOUT = 180
    __update_time = 0
    __src_addr_id = None
    __src_address = None

    def init_func(self, creator, src_addr, use_tunnel=False, bind_ip=None, is_ipv6=False):
        """
        :param creator:
        :param src_addr:
        :param use_tunnel:是否使用隧道传输
        :param bind_ip:
        :param is_ipv6:
        :return:
        """
        self.__src_addr_id = "%s-%s" % src_addr
        self.__src_address = src_addr

        if is_ipv6:
            fa = socket.AF_INET6
            if not bind_ip: bind_ip = "::"
        else:
            fa = socket.AF_INET
            if not bind_ip: bind_ip = "0.0.0.0"

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.bind((bind_ip, 0))
        self.__update_time = time.time()

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, 10)

        return self.fileno

    def udp_readable(self, message, address):
        _id = "%s-%s" % address

        if _id != self.__src_address:
            return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time() - self.__update_time

        if t > self.__TIMEOUT:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)

    def udp_error(self):
        self.delete_handler(self.fileno)
