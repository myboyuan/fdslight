#!/usr/bin/env python3
import socket, sys, time
import fdslight_etc.fn_server as fns_config
import freenet.handler.tundev as tundev
import freenet.lib.base_proto.over_tcp as over_tcp
import freenet.lib.ipaddr as ipaddr
import pywind.evtframework.handler.tcp_handler as tcp_handler
from  pywind.global_vars import global_vars

class tcp_tunnels_base(tcp_handler.tcp_handler):
    # socket超时时间
    __TIMEOUT = 60
    # 是否已经授权
    __is_auth = False

    # 加密模块
    encrypt_m = None
    # 解密模块
    decrypt_m = None

    __acts = [
        over_tcp.ACT_CLOSE,
        over_tcp.ACT_AUTH,
        over_tcp.ACT_DATA,
        over_tcp.ACT_PONG,
        over_tcp.ACT_PING
    ]

    # 客户端分配到的IP列表
    __client_ips = None
    # 是否发送了ping帧
    __is_sent_ping = False
    # 是否发送了close帧
    __is_sent_close = False
    __tun_fd = -1

    __creator_fd = -1
    # 最大缓冲区大小
    __MAX_BUFFER_SIZE = 16 * 1024
    __c_addr = None

    def init_func(self, creator_fd, s=None, c_addr=None):
        """
        :param creator_fd:
        :param tun_dev_name:在作为监听套接字的时候需要这个参数
        :param s: 服务套接字
        :param c_addr: 客户端地址
        :return:
        """

        self.decrypt_m = None
        self.encrypt_m = None
        self.__client_ips = []
        config = fns_config.configs

        if s:
            self.set_socket(s)
            self.register(self.fileno)
            self.add_evt_read(self.fileno)
            self.fn_handler_init()

            name = "freenet.lib.crypto.%s" % config["tcp_crypto_module"]
            __import__(name)
            m = sys.modules.get(name, None)

            self.encrypt_m = m.encrypt()
            self.decrypt_m = m.decrypt()

            self.__creator_fd = creator_fd
            self.__tun_fd = global_vars["freenet.tun_fd"]
            self.__c_addr = c_addr
            self.print_access_log("connect")

            return self.fileno

        bind_addr = config.get("tcp_bind_address", None)

        if not bind_addr:
            bind_addr = ("0.0.0.0", 8964)

        listen_socket = socket.socket()
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_fileno(listen_socket.fileno())
        self.set_socket(listen_socket)
        self.bind(bind_addr)

        subnet = config["subnet"]
        global_vars["freenet.ipaddr"] = ipaddr.ip4addr(*subnet)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        subnet = fns_config.configs["subnet"]

        tun_fd = self.create_handler(self.fileno, tundev.tuns, "fn_server", subnet)
        global_vars["freenet.tun_fd"] = tun_fd

    def __send_ping(self):
        """发送ping帧
        :return:
        """
        ping = self.encrypt_m.build_ping()
        self.add_evt_write(self.fileno)
        self.writer.write(ping)

    def __send_pong(self):
        """发送pong帧
        :return:
        """
        pong = self.encrypt_m.build_pong()
        self.add_evt_write(self.fileno)
        self.writer.write(pong)

    def __send_close(self):
        """发送close帧
        :return:
        """
        close = self.encrypt_m.build_close()
        self.add_evt_write(self.fileno)
        self.writer.write(close)

    def __handle_read_data(self, action, byte_data):
        if action not in self.__acts:
            print("not found action")
            self.delete_handler(self.fileno)
            return
        # 在没有验证之前丢弃所有发过来的数据包
        if not self.__is_auth and action != over_tcp.ACT_AUTH: return

        self.set_timeout(self.socket.fileno(), self.__TIMEOUT)
        if not self.__is_auth:
            if not self.fn_auth(byte_data):
                self.print_access_log("auth_fail")
                self.delete_this_no_sent_data()
                return
            self.print_access_log("auth_ok")
            self.__is_auth = True
            return

        if action == over_tcp.ACT_PING:
            self.__send_pong()
            return

        if action == over_tcp.ACT_PONG:
            self.__is_sent_ping = False
            return

        if action == over_tcp.ACT_CLOSE:
            if self.__is_sent_close:
                self.delete_handler(self.fileno)
                return
            self.__send_close()
            self.__is_sent_close = True
            return

        src_ip = byte_data[12:16]

        # 丢弃不属于客户端分配到的IP的数据包
        if src_ip not in self.__client_ips:
            return

        packet_length = (byte_data[2] << 8) | byte_data[3]

        if not self.fn_on_recv(packet_length):
            self.delete_handler(self.fileno)
            return

        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

        return

    def get_client_ips(self, n):
        """设置客户端分配到的IP地址
        :param n:需要获取的IP数量
        :return:
        """
        ipalloc = global_vars["freenet.ipaddr"]

        for i in range(n):
            packet_ip = ipalloc.get_addr()
            self.__client_ips.append(
                packet_ip
            )

        ips = []
        for packet_ip in self.__client_ips:
            ips.append(
                socket.inet_ntop(socket.AF_INET, packet_ip)
            )
        return ips

    def del_client_ips(self):
        """删除客户端分配到的IP地址"""
        ipalloc = global_vars["freenet.ipaddr"]
        while 1:
            try:
                packet_ip = self.__client_ips.pop(0)
            except IndexError:
                break
            ipalloc.put_addr(packet_ip)
        return

    def tcp_accept(self):
        while 1:
            try:
                s, addr = self.socket.accept()
            except BlockingIOError:
                break

            ret = self.fn_on_connect(s, addr)
            if not ret:
                continue
            ''''''
        return

    def tcp_readable(self):
        rdata = self.reader.read()
        self.decrypt_m.add_data(rdata)

        while self.decrypt_m.have_data():
            if not self.decrypt_m.is_ok():
                break
            action = self.decrypt_m.header_info()
            byte_data = self.decrypt_m.body_data()
            self.decrypt_m.reset()
            self.__handle_read_data(action, byte_data)
        return

    def tcp_writable(self):
        self.set_timeout(self.fileno, self.__TIMEOUT)
        self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.print_access_log("close")
        self.unregister(self.fileno)
        self.socket.close()

        self.fn_handler_clear()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.__is_auth:
            self.print_access_log("auth_timeout")
            self.delete_handler(self.fileno)
            return
        if self.__is_sent_ping or self.__is_sent_close:
            self.delete_handler(self.fileno)
            return

        self.__send_ping()

    def message_from_handler(self, from_fd, byte_data):
        # 防止发送缓冲区过大以至于过度消耗内存
        if self.writer.size() > self.__MAX_BUFFER_SIZE:
            return

        tun_fd = global_vars["freenet.tun_fd"]

        if from_fd != tun_fd:
            return

        packet_length = (byte_data[2] << 8) | byte_data[3]

        if not self.fn_on_send(packet_length):
            self.delete_handler(self.fileno)
            return

        self.encrypt_m.set_body_size(packet_length)
        hdr = self.encrypt_m.wrap_header(over_tcp.ACT_DATA)
        body = self.encrypt_m.wrap_body(byte_data)

        self.encrypt_m.reset()

        self.add_evt_write(self.fileno)
        self.writer.write(hdr)
        self.writer.write(body)

    def __build_log(self, text):
        t = time.strftime("time:%Y-%m-%d %H:%M:%S")
        ipaddr = "%s:%s" % (self.__c_addr)

        return "%s      %s      %s" % (text, ipaddr, t)

    def print_access_log(self, text):
        print(self.__build_log(text))

    def fn_handler_init(self):
        """当创建新的handler时候,将会调用这个函数进行一些初始化操作,重写这个方法
        :return:
        """
        pass

    def fn_on_connect(self, sock, caddr):
        """重写这个方法,当连接刚刚建立成功的时候
        注意:这个函数会在监听handler中调用,即还没有为这个socket创建新的服务handler
        :param sock:客户端socket对象
        :param caddr:客户端地址
        :return Boolean:True表示继续执行,False表示不继续执行
        """
        return True

    def fn_auth(self, auth_info):
        """重写这个方法,当用户需要验证的时候调用这个函数
        :param auth_info:
        :return Boolean: True表示验证成功,False表示验证失败
        """
        return True

    def fn_on_recv(self, recv_size):
        """当有数据包来的时候会调用这个函数,主要用来统计进来的流量
        :param recv_size:接收的数据包大小
        :return Boolean： True表示继续执行，False表示中断执行
        """
        return True

    def fn_on_send(self, send_size):
        """当有数据包出去的时候会调用这个函数,主要用来统计出去的流量
        :param send_size:发送的数据包大小
        :return Boolean： True表示继续执行，False表示中断执行
        """
        return True

    def fn_handler_clear(self):
        """主要用来进行用户扩展的清理操作,这在调用self.tcp_delete的时候会调用此函数
        :return:
        """
        pass
