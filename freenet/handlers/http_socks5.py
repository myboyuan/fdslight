#!/usr/bin/env python3
"""HTTP socks5代理
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time, struct, random
import pywind.web.lib.httputils as httputils
import freenet.lib.base_proto.app_proxy as app_proxy_proto


class http_socks5_listener(tcp_handler.tcp_handler):
    __cookie_ids = None
    __host_match = None

    def init_func(self, creator, address, host_match, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__cookie_ids = None
        self.__host_match = host_match

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
                self.create_handler(self.fileno, cs, caddr, self.__host_match)
        return

    def __bind_cookie_id(self, fileno):
        n = 0
        cookie_id = -1
        while n < 10:
            v = random.randint(1, 65535)
            if v not in self.__cookie_ids:
                cookie_id = v
                break
            n += 1
        if cookie_id > 0: self.__cookie_ids[cookie_id] = fileno

        return cookie_id

    def __unbind_cookie_id(self, cookie_id):
        if cookie_id not in self.__cookie_ids: return
        del self.__cookie_ids[cookie_id]

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def msg_from_tunnel(self, message):
        size = len(message)
        if size < 2: return

        cookie_id = (message[0] << 8) | message[1]
        if cookie_id not in self.__cookie_ids: return

        fileno = self.__cookie_ids[cookie_id]
        self.send_message_to_handler(self.fileno, fileno, message)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "bind_cookie_id":
            fileno, = args
            return self.__bind_cookie_id(fileno)
        if cmd == "unbind_cookie_id":
            cookie_id, = args
            self.__unbind_cookie_id(cookie_id)
            return


class _http_socks5_handler(tcp_handler.tcp_handler):
    __caddr = None
    __is_udp = None
    __fileno = None
    __step = 0

    # 是否是HTTP代理
    __is_http = None

    __is_ipv6 = None

    __use_tunnel = None
    __host_match = None
    __creator = None

    __req_ok = None

    def init_func(self, creator, cs, caddr, host_match):
        self.set_socket(cs)
        self.__is_udp = False
        self.__caddr = caddr
        self.__fileno = -1
        self.__step = 1
        self.__is_http = False
        self.__is_ipv6 = False
        self.__use_tunnel = False
        self.__host_match = host_match
        self.__creator = creator
        self.__req_ok = False

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def __handle_socks5_step1(self):
        if self.reader.size() < 2:
            self.delete_handler(self.fileno)
            return

        byte_data = self.reader.read(2)
        ver, nmethods = struct.unpack("!bb", byte_data)

        if ver != 5:
            self.__is_http = True
            self.reader.push(byte_data)
            self.__handle_http_step1()
            return

        self.reader.read()
        sent_data = struct.pack("!bb", 5, 0)
        self.__send_data(sent_data)
        self.__step = 2

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
            self.__is_ipv6 = True
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

        if cmd == 1:
            self.__fileno = self.create_handler(
                self.fileno, _tcp_client, (addr, port,), is_ipv6=self.__is_ipv6
            )
            return

        self.__fileno = self.create_handler(
            self.fileno, _udp_handler, self.__creator, (self.__caddr[0], port,),
            use_tunnel=self.__use_tunnel, is_ipv6=self.__is_ipv6
        )

    def __handle_socks5_step3(self):
        rdata = self.reader.read()
        self.send_message_to_handler(self.fileno, self.__fileno, rdata)

    def __handle_http_step1(self):
        rdata = self.reader.read()
        p = rdata.find("\r\n\r\n")

        if p < 4:
            self.delete_handler(self.fileno)
            return

        p += 4
        header_data = rdata[0:p]
        try:
            request, mapv = httputils.parse_htt1x_request_header(header_data.decode("iso-8859-1"))
        except httputils.Http1xHeaderErr:
            self.delete_handler(self.fileno)
            return

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

    def message_from_handler(self, from_fd, message):
        if from_fd == self.__fileno:
            self.__send_data(message)
            return

        if not self.__req_ok:
            try:
                cookie_id, resp_code = app_proxy_proto.parse_respconn(message)
            except app_proxy_proto.ProtoErr:
                self.delete_handler(self.fileno)
                return

            if resp_code:
                self.__req_ok = True
            else:
                self.delete_handler(self.fileno)
            return

        try:
            cookie_id, is_close, byte_data = app_proxy_proto.parse_tcp_data(message)
        except app_proxy_proto.ProtoErr:
            self.delete_handler(self.fileno)
            return

        if is_close:
            self.delete_this_no_sent_data()
            return

        self.__send_data(byte_data)


class _tcp_client(tcp_handler.tcp_handler):
    __TIMEOUT = 300
    __update_time = 0
    __creator = None

    def init_func(self, creator, address, is_ipv6=False):
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
        rdata = self.reader.read(ƒ)
        self.send_message_to_handler(self.fileno, self.__creator, rdata)

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


class UdpProtoErr(Exception):
    pass


def _parse_udp_data(byte_data):
    size = len(byte_data)
    if size < 8: raise UdpProtoErr("wrong udp socks5 protocol")

    rsv, frag, atyp = struct.unpack("!Hbb", byte_data[0:4])
    if atyp not in (1, 3, 4,): raise UdpProtoErr("unsupport atyp value")

    if atyp == 1:
        if size < 11: raise UdpProtoErr("wrong udp socks5 protocol")
        host = socket.inet_ntop(socket.AF_INET, byte_data[4:8])
        port = (byte_data[8] << 8) | byte_data[9]
        e = 10
    elif atyp == 4:
        if size < 23: raise UdpProtoErr("wrong udp socks5 protocol")
        host = socket.inet_ntop(socket.AF_INET6, byte_data[4:20])
        port = (byte_data[20] << 8) | byte_data[21]
        e = 22
    else:
        addr_len = byte_data[4]
        if addr_len + 8 > size: raise UdpProtoErr("wrong udp socks5 protocol")
        e = 5 + addr_len
        host = byte_data[5:e].decode("iso-8859-1")
        a, b = (e, e + 1,)
        port = (byte_data[a] << 8) | byte_data[b]
        e = addr_len + 7

    return (
        frag, atyp, host, port, byte_data[e:]
    )


def _build_udp_data(frag, atyp, host, port, byte_data):
    if atyp not in (1, 3, 4,): raise ValueError("wrong atyp value")

    size = 0

    if atyp == 1:
        fmt = "!Hbb4sH"
        byte_host = socket.inet_pton(socket.AF_INET, host)
    elif atyp == 4:
        fmt = "!Hbb16sH"
        byte_host = socket.inet_pton(socket.AF_INET6, host)
    else:
        byte_host = host.encode("iso-8859-1")
        size = len(byte_host)
        fmt = "!Hbbb%ssH" % size

    if atyp != 3:
        header_data = struct.pack(fmt, 0, frag, atyp, byte_host, port)
    else:
        header_data = struct.pack(fmt, 0, frag, atyp, size, byte_host, port)

    return b"".join([header_data, byte_data])


class _udp_handler(udp_handler.udp_handler):
    __TIMEOUT = 180
    __update_time = 0
    __src_addr_id = None
    __src_address = None

    __use_tunnel = None
    __permits = None
    __creator = None
    __is_ipv6 = None

    __ctl_fileno = None

    def init_func(self, creator, ctl_fileno, src_addr, host_match=None, use_tunnel=False, bind_ip=None, is_ipv6=False):
        """
        :param creator:
        :param ctl_fileno:
        :param src_addr:
        :param host_match
        :param use_tunnel:是否使用隧道传输,如果为True那么会跳过host match,当主机为域名时
        :param bind_ip:
        :param is_ipv6:
        :return:
        """
        self.__src_addr_id = "%s-%s" % src_addr
        self.__src_address = src_addr
        self.__use_tunnel = use_tunnel
        self.__permits = {}
        self.__creator = creator
        self.__is_ipv6 = is_ipv6
        self.__ctl_fileno = ctl_fileno

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

        addr, port = self.getsockname()

        self.ctl_handler(self.fileno, self.__creator, "tell_ok", addr, port)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, 10)

        return self.fileno

    def udp_readable(self, message, address):
        _id = "%s-%s" % address

        if _id == self.__src_address:
            try:
                atyp, frag, host, port, byte_data = _parse_udp_data(message)
            except UdpProtoErr:
                return
            # 丢弃分包
            if frag != 0: return
            if self.__use_tunnel:
                return
            if self.__is_ipv6 and (atyp not in (3, 4,)): return
            if not self.__is_ipv6 and (atyp not in (1, 3)): return

            self.__update_time = time.time()
            self.__permits[port] = None
            self.sendto(byte_data, (host, port,))
            self.add_evt_write(self.fileno)
            return

        # 如果使用隧道传输,丢弃非隧道的包
        if self.__use_tunnel: return
        # 进行端口限制
        if address[1] not in self.__permits: return

        if self.__is_ipv6:
            atyp = 4
        else:
            atyp = 1

        sent_data = _build_udp_data(0, atyp, address[0], address[1], message)

        self.sendto(sent_data, self.__src_address)
        self.add_evt_write(self.fileno)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time() - self.__update_time

        if t > self.__TIMEOUT:
            self.ctl_handler(self.fileno, self.__creator, "tell_close")
            return

        self.set_timeout(self.fileno, 10)

    def udp_error(self):
        self.ctl_handler(self.fileno, self.__creator, "tell_close")
