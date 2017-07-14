#!/usr/bin/env python3
"""HTTP socks5代理
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time, struct, random
import pywind.web.lib.httputils as httputils
import freenet.lib.base_proto.app_proxy as app_proxy_proto
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.utils as utils


def _parse_http_uri_with_tunnel_mode(uri):
    """解析隧道模式HTTP URI
    :param uri:
    :param tunnel_mode:是否是隧道模式
    :return:
    """

    p = uri.find(":")
    if p < 1: return None
    host = uri[0:p]

    p += 1
    try:
        port = int(uri[p:])
    except ValueError:
        return None

    return (host, port,)


def _parse_http_uri_no_tunnel_mode(uri):
    """解析非隧道模式HTTP URI
    :param uri:
    :return:
    """
    if uri[0:7] != "http://": return None

    port = 80
    sts = uri[7:]

    p = sts.find("/")
    if p < 0: return None

    e = p
    t = sts[0:p]
    p = t.find(":")

    if p > 0:
        host = t[0:p]
        p += 1
        try:
            port = int(t[p:])
        except ValueError:
            return None
        ''''''
    else:
        host = t[0:e]

    return (host,
            port,
            sts[e:],)


class http_socks5_listener(tcp_handler.tcp_handler):
    __cookie_ids = None
    __host_match = None
    __debug = None

    def init_func(self, creator, address, host_match, is_ipv6=False, debug=True):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__cookie_ids = {}
        self.__host_match = host_match
        self.__debug = debug

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
                self.create_handler(
                    self.fileno, _http_socks5_handler,
                    cs, caddr, self.__host_match,
                    debug=self.__debug
                )
            except BlockingIOError:
                break
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

    def del_all_proxy(self):
        seq = [v for k, v in self.__cookie_ids.items()]
        for fileno in seq:
            self.delete_handler(fileno)
        return


class _http_socks5_handler(tcp_handler.tcp_handler):
    __caddr = None
    __is_udp = None
    __fileno = None
    __step = 0

    # 是否是HTTP代理
    __is_http = None
    # 是否是http隧道代理
    __is_http_tunnel = None

    __is_ipv6 = None

    __use_tunnel = None
    __host_match = None
    __creator = None

    __req_ok = None
    # 是否已经发送过代理请求
    __is_sent_proxy_request = None

    __cookie_id = 0

    # UDP数据发送缓冲区
    __sentdata_buf = None
    __update_time = 0
    __TIMEOUT = 300

    __debug = None

    def init_func(self, creator, cs, caddr, host_match, debug=True):
        self.set_socket(cs)
        self.__is_udp = False
        self.__caddr = caddr
        self.__fileno = -1
        self.__step = 1
        self.__is_http = False
        self.__is_http_tunnel = False
        self.__is_ipv6 = False
        self.__use_tunnel = False
        self.__host_match = host_match
        self.__creator = creator
        self.__req_ok = False
        self.__sentdata_buf = []
        self.__is_sent_proxy_request = False
        self.__debug = debug

        self.set_timeout(self.fileno, 15)

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
            if atyp == 3:
                is_match, flags = self.__host_match.match(addr)

                if is_match and flags == 1:
                    self.__use_tunnel = True
                    self.__tunnel_proxy_reqconn(atyp, addr, port)
                    return
            self.__fileno = self.create_handler(
                self.fileno, _tcp_client, (addr, port,), is_ipv6=self.__is_ipv6
            )
            return

        self.__is_udp = True
        self.__fileno = self.create_handler(
            self.fileno, _udp_handler, (self.__caddr[0], port,), self.__host_match,
            is_ipv6=self.__is_ipv6
        )

    def __handle_socks5_step3(self):
        rdata = self.reader.read()

        if self.__use_tunnel:
            self.__tunnel_proxy_send_tcpdata(rdata)
        else:
            self.send_message_to_handler(self.fileno, self.__fileno, rdata)
        return

    def __handle_http_step1(self):
        rdata = self.reader.read()
        p = rdata.find(b"\r\n\r\n")

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

        body_data = rdata[p:]

        # 使用隧道模式
        if request[0].lower() == "connect":
            self.__handle_http_tunnel_proxy(request, mapv)
            return

        self.__handle_http_no_tunnel_proxy(request, mapv, body_data)

    def __get_atyp(self, host):
        """根据host获取socks5 atyp值
        :param host:
        :return:
        """
        if utils.is_ipv4_address(host):
            return 1

        if utils.is_ipv6_address(host):
            return 4

        return 3

    def __handle_http_tunnel_proxy(self, request, mapv):
        rs = _parse_http_uri_with_tunnel_mode(request[1])

        if not rs:
            self.delete_handler(self.fileno)
            return

        self.__is_http_tunnel = True

        host, port = rs
        is_match, flags = self.__host_match.match(host)

        if self.__debug: print("%s:%s" % (host, port,))

        if is_match and flags == 1:
            self.__use_tunnel = True
            atyp = self.__get_atyp(host)
            self.__tunnel_proxy_reqconn(atyp, host, port)
            return

        self.__fileno = self.create_handler(
            self.fileno, _tcp_client, (host, port,), is_ipv6=self.__is_ipv6
        )

    def __handle_http_no_tunnel_proxy(self, request, mapv, body_data):
        rs = _parse_http_uri_no_tunnel_mode(request[1])

        if not rs:
            self.delete_handler(self.fileno)
            return

        host, port, uri = rs
        seq = []

        if self.__debug: print("%s:%s" % (host, port,))

        # 去除代理信息
        for k, v in mapv:
            if k.lower() == "proxy-connection": continue
            seq.append((k, v,))

        # 重新构建HTTP请求头部
        header_data = httputils.build_http1x_req_header(request[0], uri, seq)
        req_data = b"".join([header_data.encode("iso-8859-1"), body_data])

        is_match, flags = self.__host_match.match(host)

        if is_match and flags:
            self.__use_tunnel = True
            atyp = self.__get_atyp(host)
            self.__tunnel_proxy_reqconn(atyp, host, port)
            self.__sentdata_buf.append(req_data)
            return

        self.__fileno = self.create_handler(
            self.fileno, _tcp_client, (host, port,), is_ipv6=self.__is_ipv6
        )
        self.send_message_to_handler(self.fileno, self.__fileno, req_data)
        self.__step = 2

    def __response_http_tunnel_proxy_handshake(self):
        """响应HTTP隧道代理结果
        :return:
        """
        resp_data = httputils.build_http1x_resp_header("200 Connection Established", [])
        self.__send_data(resp_data.encode("iso-8859-1"))

    def __handle_http_step2(self):
        rdata = self.reader.read()

        if self.__use_tunnel:
            self.__tunnel_proxy_send_tcpdata(rdata)
        else:
            self.send_message_to_handler(self.fileno, self.__fileno, rdata)
        return

    def __handle_http(self):
        if self.__step == 1:
            self.__handle_http_step1()
            return

        self.__handle_http_step2()

    def __handle_socks5(self):
        if self.__step == 1:
            self.__handle_socks5_step1()
            return

        if self.__step == 2:
            self.__handle_socks5_step2()
            return

        self.__handle_socks5_step3()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd not in (
                "tell_socks_ok", "tell_error", "tell_close",
                "udp_tunnel_send",
        ): return

        if cmd == "tell_close":
            self.delete_this_no_sent_data()
            return

        if self.__is_http:
            if cmd == "tell_socks_ok":
                self.__step = 2
                if not self.__is_http_tunnel: return
                self.__response_http_tunnel_proxy_handshake()
                return
            if cmd == "tell_error":
                self.delete_handler(self.fileno)
                return
            if cmd == "tell_socks_ok": self.__step = 2
            return

        if cmd == "udp_tunnel_send":
            atyp, addr, port, byte_data = args

            if not self.__is_sent_proxy_requst:
                if atyp == 4:
                    _addr = "::"
                else:
                    _addr = "0.0.0.0"
                self.__tunnel_proxy_reqconn(atyp, 3, _addr, 0)
            self.__tunnel_proxy_send_udpdata(self.__cookie_id, atyp, addr, port, byte_data)
            return

        if cmd == "tell_socks_ok":
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

        if cmd == "tell_socks_ok":
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
        if self.handler_exists(self.__fileno): return

        t = time.time() - self.__update_time
        if t > self.__TIMEOUT:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        self.ctl_handler(self.fileno, self.__creator, "unbind_cookie_id", self.__cookie_id)

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
                if self.__is_http:
                    self.handler_ctl(self.fileno, "tell_socks_ok")
                else:
                    self.__step = 3
                    addrinfo = self.socket.getsockname()
                    self.handler_ctl(self.fileno, "tell_socks_ok", addrinfo[0], addrinfo[1])
            else:
                self.delete_handler(self.fileno)
                return
            # 发送缓冲区的数据
            while 1:
                try:
                    sent_data = self.__sentdata_buf.pop(0)
                except IndexError:
                    break
                self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_SOCKS, sent_data)
            return
            ''''''

        if self.__is_udp:
            try:
                is_ipv6, is_domain, cookie_id, host, port, byte_data = app_proxy_proto.parse_udp_data(message)
            except app_proxy_proto.ProtoErr:
                return
            self.ctl_handler(self.fileno, self.__fileno, "udp_data", host, port, byte_data)
            return

        try:
            cookie_id, is_close, byte_data = app_proxy_proto.parse_tcp_data(message)
        except app_proxy_proto.ProtoErr:
            self.delete_handler(self.fileno)
            return

        self.__update_time = time.time()

        if is_close:
            self.delete_this_no_sent_data()
            return

        self.__send_data(byte_data)

    def __tunnel_proxy_reqconn(self, atyp, addr, port):
        if self.__is_sent_proxy_request: return

        self.__cookie_id = self.ctl_handler(self.fileno, self.__creator, "bind_cookie_id", self.fileno)

        if self.__cookie_id < 0:
            self.delete_handler(self.fileno)
            return

        self.__is_sent_proxy_request = True
        sent_data = app_proxy_proto.build_reqconn(self.__cookie_id, 1, atyp, addr, port)
        self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_SOCKS, sent_data)

    def __tunnel_proxy_send_tcpdata(self, tcpdata):
        self.__update_time = time.time()

        sent_data = app_proxy_proto.build_tcp_send_data(self.__cookie_id, tcpdata)

        self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_SOCKS, sent_data)

    def __tunnel_proxy_send_udpdata(self, cookie_id, atyp, address, port, udpdata):
        sent_data = app_proxy_proto.build_udp_send_data(
            cookie_id, atyp, address, port, udpdata
        )

        if not self.__req_ok:
            self.__sentdata_buf.append(sent_data)
        else:
            self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_SOCKS, sent_data)


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
            "tell_socks_ok", address, port
        )

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        if self.writer.size() > 0: self.add_evt_write(self.fileno)

    def tcp_readable(self):
        rdata = self.reader.read()
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

        if self.is_conn_ok(): self.add_evt_write(self.fileno)


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

    __permits = None
    __creator = None
    __is_ipv6 = None
    __host_match = None

    def init_func(self, creator, src_addr, host_match, bind_ip=None, is_ipv6=False):
        """
        :param creator:
        :param src_addr:
        :param host_match
        :param bind_ip:
        :param is_ipv6:
        :return:
        """
        self.__src_addr_id = "%s-%s" % src_addr
        self.__src_address = src_addr
        self.__permits = {}
        self.__creator = creator
        self.__is_ipv6 = is_ipv6
        self.__host_match = host_match

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

        self.ctl_handler(self.fileno, self.__creator, "tell_socks_ok", addr, port)

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
            if self.__is_ipv6 and (atyp not in (3, 4,)): return
            if not self.__is_ipv6 and (atyp not in (1, 3)): return

            self.__update_time = time.time()
            self.__permits[port] = None

            is_match = False
            flags = 0

            if atyp == 3:
                is_match, flags = self.__host_match.match(host)

            if is_match and flags == 1:
                self.ctl_handler(self.fileno, self.__creator, "udp_tunnel_send", atyp, host, port, byte_data)
                return

            self.sendto(byte_data, (host, port,))
            self.add_evt_write(self.fileno)
            return

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

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "udp_data": return

        address, port, byte_data = args
        if port not in self.__permits: return

        self.sendto(byte_data, (address, port))
        self.add_evt_write(self.fileno)
