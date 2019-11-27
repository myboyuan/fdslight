#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.httputils as httputils
import pywind.lib.timer as timer

import socket, time,struct

import freenet.lib.logging as logging
import freenet.lib.socks2https as socks2https

# 表示主机地址是IP地址
HTTP_HOST_IP = 0
# 表示主机地址是IPv6地址
HTTP_HOST_IPv6 = 1
# 表示主机地址是域名
HTTP_HOST_DOMAIN = 2


class listener(tcp_handler.tcp_handler):
    def init_func(self, creator_fd, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class http_socks5_listener(listener):
    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, http_socks5_handler, cs, caddr)
        ''''''


class http_socks5_handler(tcp_handler.tcp_handler):
    ### 是否是socks5请求
    __is_socks5 = None
    ### http请求相关变量
    # 是否已经解析了http请求头
    __is_parsed_http_header = None
    # 是否是http隧道模式
    __is_http_tunnel_mode = None
    # 响应是否结束
    __http_request_info = None
    __http_request_kv_pairs = None
    __http_uri = None
    __http_response_header_ok = None

    ### socks5相关变量
    # socks5是否握手成功
    __socks5_handshake_ok = None
    # socks5代理连接是否建立
    __socks5_proxy_is_conn_established = None
    # 是否是socks5 udp协议
    __is_socks5_udp = None
    __socks5_request_establish_packet = None
    __socks5_atyp = None
    ### 其他相关变量
    __caddr = None
    # 是否已经确认了协议
    __is_sure_protocol = None
    # 流量是否发送到转换客户端
    __is_sent_to_convert_client = None

    __raw_client_fd = None
    __packet_id = None
    __time = None

    def init_func(self, creator_fd, cs, caddr):
        self.__is_socks5 = False
        self.__caddr = caddr
        self.__is_sure_protocol = False
        self.__is_parsed_http_header = False
        self.__http_response_header_ok = False
        self.__raw_client_fd = -1
        self.__socks5_handshake_ok = False
        self.__socks5_proxy_is_conn_established = False
        self.__is_socks5_udp = False
        self.__is_sent_to_convert_client = False
        self.__packet_id = -1
        self.__time = time.time()

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def is_need_upper_proxy(self, host, add_type):
        """检查是否需要上游代理
        :param host:
        :param add_type:该值来源自socks2https协议
        :param is_ipv6:
        :return:
        """
        rs = False
        if add_type == socks2https.ADDR_TYPE_DOMAIN:
            rs = self.dispatcher.match_domain(host)[0]
        elif add_type == socks2https.ADDR_TYPE_IP:
            # 优先匹配只有一个IP地址的网络,即DNS查询创建的临时条目
            rs = self.dispatcher.match_ip(host, is_ipv6=False, is_ip_host=True)
            if not rs: rs = self.dispatcher.match_ip(host, is_ipv6=False, is_ip_host=False)
        elif add_type == socks2https.ADDR_TYPE_FORCE_DOMAIN_IPv6:
            rs = self.dispatcher.match_domain(host)[0]
        else:
            # 优先匹配只有一个IP地址的网络,即DNS查询创建的临时条目
            rs = self.dispatcher.match_ip(host, is_ipv6=True)
            if not rs: rs = self.dispatcher.match_ip(host, is_ipv6=True, is_ip_host=False)

        return rs

    @property
    def debug(self):
        return self.dispatcher.debug

    def handle_http(self):
        if not self.__is_parsed_http_header:
            rs = self.parse_http_header()
            if not rs:
                self.delete_handler(self.fileno)
                return
            ''''''
        if not self.__is_parsed_http_header: return

        rdata = self.reader.read()

        if not self.__is_sent_to_convert_client:
            self.send_message_to_handler(self.fileno, self.__raw_client_fd, rdata)
        else:
            self.dispatcher.send_tcp_data(self.__packet_id, rdata)

    def http_request_check(self):
        # 检查uri是否合法
        if self.__http_request_info[0].lower() != "connect":
            if len(self.__http_request_info[1]) < 9: return False
            p = self.__http_request_info[1].find("http://")
            if p != 0: return False

        return True

    def http_request_set(self):
        """HTTP请求设置
        :return:
        """
        new_headers = []
        for k, v in self.__http_request_kv_pairs:
            name = k.lower()
            # 过滤到proxy相关信息,防止远程服务器知道是代理连接
            if name[0:5] == "proxy": continue
            new_headers.append((k, v,))
        self.__http_request_kv_pairs = new_headers

    def get_http_host(self, host):
        """
        :param host:
        :return:
        """
        if host[0] == "[" and host[-1] == "]":
            if len(host) < 3: return None
            host = host[1:-1]
            try:
                addr_type = HTTP_HOST_IPv6
                socket.inet_pton(socket.AF_INET6, host)
            except:
                return None

            return (host, addr_type,)

        addr_type = HTTP_HOST_IP
        try:
            addr_type = HTTP_HOST_IP
            socket.inet_pton(socket.AF_INET, host)
        except:
            addr_type = HTTP_HOST_DOMAIN
        return (host, addr_type,)

    def get_http_remote_server_info(self):
        uri = self.__http_request_info[1]
        if self.__is_http_tunnel_mode:
            p = uri.find(":")
            host = uri[0:p]
            new_host = self.get_http_host(host)
            if not new_host: return None
            p += 1
            try:
                port = int(uri[p:])
            except ValueError:
                return None
            return (new_host, port, None)

        port = 80
        new_uri = None
        host = None
        s = uri[7:]
        p = s.find("/")

        if p < 1: return None

        a = s[0:p]
        new_uri = s[p:]

        p = a.find(":")
        if p > 0:
            host = a[0:p]
            p += 1
            try:
                port = int(a[p:])
            except ValueError:
                return None
            ''''''
        else:
            host = a

        new_host = self.get_http_host(host)
        if not new_host: return None

        return (new_host, port, new_uri)

    def parse_http_header(self):
        """
        :return Boolean: True表示未发生错误,False表示发生错误
        """
        size = self.reader.size()
        rdata = self.reader.read()
        p = rdata.find(b"\r\n\r\n")

        if p < 0 and size > 2048: return False
        if p < 0:
            self.reader._putvalue(rdata)
            return True
        if p < 12: return False

        p += 4
        self.reader._putvalue(rdata[p:])
        s = rdata[0:p].decode("iso-8859-1")
        try:
            req, kv_pairs = httputils.parse_htt1x_request_header(s)
        except httputils.Http1xHeaderErr:
            return False
        # 只支持http/1.1代理
        if req[2].lower() != "http/1.1": return False

        self.__http_request_info = req
        self.__http_request_kv_pairs = kv_pairs
        self.__is_parsed_http_header = True

        if self.__http_request_info[0].lower() == "connect": self.__is_http_tunnel_mode = True

        # 核对http请求头
        if not self.http_request_check():
            if self.dispatcher.debug:
                logging.print_general("wrong http request header", self.__caddr)
            self.delete_handler(self.fileno)
            return

        server_info = self.get_http_remote_server_info()
        if not server_info:
            self.delete_handler(self.fileno)
            return
        if not self.__is_http_tunnel_mode:
            self.http_request_set()
        host_info, port, uri = server_info

        host, addr_type = host_info
        if addr_type == HTTP_HOST_IPv6:
            is_ipv6 = True
        else:
            is_ipv6 = False
        self.__http_uri = uri

        if self.debug:
            logging.print_general("http_proxy_request", (host, port,))

        if addr_type == HTTP_HOST_IPv6:
            _t = socks2https.ADDR_TYPE_IPv6
        elif addr_type == HTTP_HOST_IP:
            _t = socks2https.ADDR_TYPE_IP
        else:
            _t = socks2https.ADDR_TYPE_DOMAIN

        self.__is_sent_to_convert_client = self.is_need_upper_proxy(host, _t)

        if not self.__is_sent_to_convert_client:
            self.__raw_client_fd = self.create_handler(self.fileno, raw_tcp_client, (host, port), is_ipv6=is_ipv6)
            return True

        self.__packet_id = self.dispatcher.alloc_packet_id(self.fileno)
        self.dispatcher.send_conn_frame(socks2https.FRAME_TYPE_TCP_CONN, self.__packet_id, host, port, _t)

        return True

    def send_http_response(self, status):
        kv_pairs = [
            ("Server", "Socks2Https"),
            ("Content-Length", 0),
            ("Connection", "Keep-Alive",)
        ]
        s = httputils.build_http1x_resp_header(status, kv_pairs)

        self.add_evt_write(self.fileno)
        self.writer.write(s.encode("iso-8859-1"))

    def http_conn_ok(self):
        if self.__is_http_tunnel_mode:
            self.send_http_response("200 Connection Established")
            return
        # 重新构建http请求头部
        s = httputils.build_http1x_req_header(self.__http_request_info[0], self.__http_uri,
                                              self.__http_request_kv_pairs)
        if not self.__is_sent_to_convert_client:
            self.send_message_to_handler(self.fileno, self.__raw_client_fd, s.encode("iso-8859-1"))
        else:
            self.dispatcher.send_tcp_data(self.__packet_id, s.encode("iso-8859-1"))

    def handle_socks5_handshake(self):
        size = self.reader.size()
        if size != 3:
            self.delete_handler(self.fileno)
            return

        rdata = self.reader.read()
        v = rdata[0]
        if v != 5:
            self.delete_handler(self.fileno)
            return
        methods = []
        for i in rdata[2:]: methods.append(i)

        # 只支持无需认证方式
        if 0 not in methods:
            self.delete_handler(self.fileno)
            return

        pkt = struct.pack("!BB", 5, 0)

        self.writer.write(pkt)
        self.add_evt_write(self.fileno)
        self.__socks5_handshake_ok = True

    def handle_socks5_establish(self):
        size = self.reader.size()
        rdata = self.reader.read()
        self.__socks5_request_establish_packet = rdata

        if size < 7:
            self.delete_handler(self.fileno)
            return
        ver = rdata[0]
        cmd = rdata[1]
        rsv = rdata[2]
        atyp = rdata[3]

        if ver != 5:
            self.delete_handler(self.fileno)
            return
        # 取消bind命令的支持
        if cmd not in (1, 3,):
            self.delete_handler(self.fileno)
            return
        # 检查地址类型列表
        if atyp not in (1, 3, 4,):
            self.delete_handler(self.fileno)
            return
        if atyp == 1 and size != 10:
            self.delete_handler(self.fileno)
            return
        if atyp == 4 and size != 22:
            self.delete_handler(self.fileno)
            return
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, rdata[4:8])
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, rdata[4:20])
        else:
            length = rdata[4]
            host = rdata[5:-2].decode("iso-8859-1")
            if length != len(rdata[5:-2]):
                self.delete_handler(self.fileno)
                return
            ''''''
        b = rdata[-2:]
        port = (b[0] << 8) | b[1]
        if atyp == 4:
            is_ipv6 = True
        else:
            is_ipv6 = False

        if atyp == 4:
            _t = socks2https.ADDR_TYPE_IPv6
        elif atyp == 1:
            _t = socks2https.ADDR_TYPE_IP
        else:
            _t = socks2https.ADDR_TYPE_DOMAIN

        # 处理TCP协议
        if cmd != 3:
            if self.debug: logging.print_general("socks5_tcp_proxy", (host, port,))
            self.__is_sent_to_convert_client = self.is_need_upper_proxy(host, _t)
            if not self.__is_sent_to_convert_client:
                self.__raw_client_fd = self.create_handler(self.fileno, raw_tcp_client, (host, port), is_ipv6=is_ipv6)
                return
            self.__packet_id = self.dispatcher.alloc_packet_id(self.fileno)
            self.dispatcher.send_conn_frame(
                socks2https.FRAME_TYPE_TCP_CONN,
                self.__packet_id,
                host, port, _t
            )
            return

        if self.debug: logging.print_general("socks5_udp_proxy", (host, port,))

        self.__is_sent_to_convert_client = self.dispatcher.match_udp_src_ip(self.__caddr[0], is_ipv6=is_ipv6)
        self.__socks5_atyp = atyp
        self.__raw_client_fd = self.create_handler(self.fileno, self.__caddr[0], port,
                                                   upper_proxy=self.__is_sent_to_convert_client, is_ipv6=is_ipv6)
        self.__is_socks5_udp = True
        self.__socks5_handshake_ok = True

        if not self.__is_sent_to_convert_client: self.send_socks5_udp_handshake()

    def send_socks5_udp_handshake(self):
        if self.__socks5_atyp == 4:
            is_ipv6 = True
        else:
            is_ipv6 = False
        a = struct.pack("!BBBB", 5, 0, 0, self.__socks5_atyp)
        bind_address = self.dispatcher.get_handler(self.__raw_client_fd).bind_address
        if is_ipv6:
            net_addr = socket.inet_pton(socket.AF_INET6, bind_address[0])
        else:
            net_addr = socket.inet_pton(socket.AF_INET, bind_address[0])
        b = struct.pack("!H", bind_address[1])
        pkt = b"".join([a, net_addr, b])
        self.writer.write(pkt)
        self.add_evt_write(self.fileno)

    def handle_socks5_data(self):
        rdata = self.reader.read()

        if self.__is_sent_to_convert_client:
            self.dispatcher.send_tcp_data(self.__packet_id, rdata)
            return

        self.send_message_to_handler(self.fileno, self.__raw_client_fd, rdata)

    def handle_socks5(self):
        if not self.__socks5_handshake_ok:
            self.handle_socks5_handshake()
            return
        if not self.__socks5_proxy_is_conn_established:
            self.handle_socks5_establish()
            return
        # 握手成功后不允许再发送TCP数据包
        if self.__is_socks5_udp:
            self.delete_handler(self.fileno)
            return
        self.handle_socks5_data()

    def handle_socks5_conn_ok(self):
        if self.__is_socks5_udp:
            self.send_socks5_udp_handshake()
            return

        seq = list(self.__socks5_request_establish_packet)
        seq[1] = 0
        byte_data = bytes(seq)
        self.__socks5_proxy_is_conn_established = True
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)

    def tcp_readable(self):
        ### 首先确认协议
        if not self.__is_sure_protocol:
            rdata = self.reader.read()
            if not rdata: return
            if rdata[0] == 5:
                self.__is_socks5 = True
            else:
                self.__is_socks5 = False
            self.__is_sure_protocol = True
            self.reader._putvalue(rdata)

        if self.__is_socks5:
            self.handle_socks5()
        else:
            self.handle_http()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > self.dispatcher.socks5http_conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        if self.__raw_client_fd > 0:
            self.delete_handler(self.__raw_client_fd)
        if self.__packet_id > 0:
            self.dispatcher.free_packet_id(self.__packet_id)
        self.unregister(self.fileno)
        self.close()

    def tell_close(self):
        self.delete_handler(self.fileno)

    def tell_conn_ok(self):
        if self.__is_socks5:
            self.handle_socks5_conn_ok()
        else:
            self.http_conn_ok()

    def message_from_handler(self, from_fd, byte_data):
        if not self.__is_sure_protocol: return
        self.__time = time.time()
        self.writer.write(byte_data)

        # 防止数据接收过多
        if self.writer.size() > 0xffffff:
            self.writer._getvalue()
            return

        if not self.__is_socks5 and not self.__is_http_tunnel_mode:
            if not self.__http_response_header_ok:
                rs = self.handle_http_response_header()
                if not rs:
                    self.delete_handler(self.fileno)
                    return
                ''''''
            self.add_evt_write(self.fileno)
            return
        self.add_evt_write(self.fileno)

    def handle_http_response_header(self):
        size = self.writer.size()
        rdata = self.writer._getvalue()

        p = rdata.find(b"\r\n\r\n")
        if p < 0 and size > 4096: return False
        if p < 12: return False

        p += 4
        try:
            resp, kv_pairs = httputils.parse_http1x_response_header(rdata[0:p].decode("iso-8859-1"))
        except httputils.Http1xHeaderErr:
            return False

        # 重写头部连接字段,数据传输完毕后就关闭连接
        resp_headers = []
        for k, v in kv_pairs:
            if k.lower() == "connection":
                resp_headers.append(("Connection", "close",))
                continue
            resp_headers.append((k, v,))
        data = httputils.build_http1x_resp_header(resp[1], resp_headers)

        self.writer.write(data.encode("iso-8859-1"))
        self.writer.write(rdata[p:])
        self.__http_response_header_ok = True

        return True


class raw_tcp_client(tcp_handler.tcp_handler):
    __caddr = None
    __creator = None
    __time = None
    __wait_sent = None
    __wait_sent_size = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__creator = creator_fd
        self.__time = time.time()
        self.__wait_sent = []
        self.__wait_sent_size = 0

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)

        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.add_evt_write(self.fileno)
        while 1:
            try:
                data = self.__wait_sent.pop(0)
            except IndexError:
                break
            self.writer.write(data)

        self.dispatcher.get_handler(self.__creator).tell_conn_ok()

    def tcp_readable(self):
        rdata = self.reader.read()
        if not self.handler_exists(self.__creator): return
        self.__time = time.time()
        self.send_message_to_handler(self.fileno, self.__creator, rdata)

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.dispatcher.get_handler(self.__creator).tell_close()
            return

        t = time.time()
        if t - self.__time < self.dispatcher.socks5http_conn_timeout:
            self.set_timeout(self.fileno, 10)
            return

        self.dispatcher.get_handler(self.__creator).tell_close()

    def tcp_error(self):
        self.dispatcher.get_handler(self.__creator).tell_close()

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, byte_data):
        if not self.is_conn_ok():
            # 防止客户端恶意传送大量数据
            if self.__wait_sent_size > 0xffff: return
            self.__wait_sent.append(byte_data)
            return

        self.__time = time.time()
        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)


class raw_udp_client(udp_handler.udp_handler):
    __time = None
    __client_ip = None
    __client_port = None
    __listen_ip = None
    __is_ipv6 = None

    # 访问列表,增加UDP安全性
    __access_list = None
    __timer = None
    __packet_id = None
    __upper_proxy = None

    def init_func(self, creator_fd, client_ip, client_port, upper_proxy=False, is_ipv6=False):
        self.__creator = creator_fd
        self.__time = time.time()
        self.__client_ip = client_ip
        self.__client_port = client_port
        self.__is_ipv6 = is_ipv6
        self.__access_list = {}
        self.__timer = timer.timer()
        self.__upper_proxy = upper_proxy

        if is_ipv6:
            listen_ip = self.dispatcher.socks5_listen_ipv6
        else:
            listen_ip = self.dispatcher.socks5_listen_ip

        self.__listen_ip = listen_ip
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.bind((listen_ip, 0))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        if self.__upper_proxy:
            self.__packet_id = self.dispatcher.alloc_packet_id()
            if is_ipv6:
                addr_type = socks2https.ADDR_TYPE_IPv6
            else:
                addr_type = socks2https.ADDR_TYPE_IP
            self.dispatcher.send_conn_frame(
                socks2https.FRAME_TYPE_UDP_CONN,
                self.__packet_id, client_ip, client_port, addr_type
            )

        return self.fileno

    @property
    def bind_address(self):
        return (self.__listen_ip, self.getsockname()[1],)

    def handle_udp_packet_from_client(self, message):
        msg_size = len(message)
        # 检查数据包合法性
        if msg_size < 9: return None
        rsv, frag, atyp, = struct.unpack("!HBB", message[0:4])
        if rsv != 0: return None
        # 不支持UDP分包
        if frag != 0: return None

        if atyp not in (1, 3, 4,): return None
        if atyp == 1 and msg_size < 11: return None
        if atyp == 4 and msg_size < 23: return None

        message = message[4:]

        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, message[0:4])
            message = message[4:]
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, message[0:16])
            message = message[16:]
        else:
            length = message[0]
            e = 1 + length
            size = len(message[1:e])
            if size != length: return None
            host = message[1:e].decode("iso-8859-1")
            message = message[1:]

        port = (message[0] << 8) | message[1]
        message = message[2:]

        return (host, port, atyp, message,)

    def handle_udp_packet_from_server(self, message, address):
        if not self.handler_exists(self.__creator): return
        # 检查客户端是否发送过数据包
        if address[0] not in self.__access_list: return
        if self.__is_ipv6:
            net_addr = socket.inet_pton(socket.AF_INET6, address[0])
        else:
            net_addr = socket.inet_pton(socket.AF_INET, address[0])

        if self.__is_ipv6:
            atyp = 4
        else:
            atyp = 1

        a = struct.pack("!HBB", 0, 0, atyp)
        b = struct.pack("!H", address[1])

        msg = b"".join([a, net_addr, b, message])
        self.sendto(msg, (self.__client_ip, self.__client_port,))
        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        if address[0] != self.__client_ip:
            self.handle_udp_packet_from_server(message, address)
            return
        # 检查客户端的端口
        if self.__client_port != address[1]: return
        rs = self.handle_udp_packet_from_client(message)
        if not rs:
            self.dispatcher.get_handler(self.__creator).tell_close()
            return

        host, port, addr_type, msg = rs
        # 检查数据包IP协议是否和协商不一致
        if not self.__is_ipv6 and addr_type == 4:
            self.dispatcher.get_handler(self.__creator).tell_close()
            return
        if self.__is_ipv6 and addr_type == 1:
            self.dispatcher.get_handler(self.__creator).tell_close()
            return

        self.__timer.set_timeout(host, 60)
        self.__time = time.time()
        if host not in self.__access_list:
            self.__access_list[host] = None

        self.sendto(msg, (host, port,))
        self.add_evt_write(self.fileno)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        t = time.time()
        if t - self.__time > self.dispatcher.socks5http_conn_timeout:
            self.dispatcher.get_handler(self.__creator).tell_close()
            return

        names = self.__timer.get_timeout_names()
        for name in names:
            if name in self.__timer.exists(name):
                self.__timer.drop(name)
            if name in self.__access_list:
                del self.__access_list[name]
            ''''''
        self.set_timeout(self.fileno, 10)

    def handle_udp_udplite_data(self, address, message):
        self.handle_udp_packet_from_server(message, address)

    def udp_error(self):
        self.dispatcher.get_handler(self.__creator).tell_close()

    def udp_delete(self):
        if self.__upper_proxy:
            self.dispatcher.free_packet_id(self.__packet_id)
        self.unregister(self.fileno)
        self.close()

    def tell_conn_ok(self):
        self.dispatcher.get_handler(self.__creator).tell_conn_ok()

    def tell_close(self):
        self.dispatcher.get_handler(self.__creator).tell_close()
