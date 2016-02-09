#!/usr/bin/env python3
"""
隧道客户端基本类
"""
import json
import socket
import sys

import fdslight_etc.fn_client as fnc_config
import freenet.handler.tundev as tundev
import freenet.lib.base_proto.over_tcp as over_tcp
import pywind.evtframework.handler.tcp_handler as tcp_handler


class tcp_tunnelc_base(tcp_handler.tcp_handler):
    __tun_fd = -1
    __encrypt_m = None
    __decrypt_m = None
    __TIMEOUT = 50
    # 是否已经发送过验证报文
    __is_sent_auth = False

    ___acts = [
        over_tcp.ACT_AUTH,
        over_tcp.ACT_CLOSE,
        over_tcp.ACT_PING,
        over_tcp.ACT_PONG,
        over_tcp.ACT_DATA
    ]

    # 是否发送过ping
    __is_sent_ping = False

    # 最大缓冲区大小
    __MAX_BUFFER_SIZE = 16 * 1024

    def init_func(self, creator_fd):
        server_addr = fnc_config.configs["tcp_server_address"]

        s = socket.socket()

        s.connect(server_addr)
        self.set_socket(s)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.add_evt_write(self.fileno)

        self.__tun_fd = self.create_handler(self.fileno, tundev.tunc, "fn_client")

        name = "freenet.lib.crypto.%s" % fnc_config.configs["tcp_crypto_module"]
        __import__(name)
        m = sys.modules[name]
        self.__encrypt_m = m.encrypt()
        self.__decrypt_m = m.decrypt()

        return self.fileno

    def __send_ping(self):
        """发送ping帧
        :return:
        """
        self.__is_sent_ping = True
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

    def __send_auth(self, pydict):
        self.__is_sent_auth = True
        sts = json.dumps(pydict)
        data_size = len(sts)
        self.encrypt_m.set_body_size(data_size)
        hdr = self.encrypt_m.wrap_header(over_tcp.ACT_AUTH)
        body = self.encrypt_m.wrap_body(sts.encode("utf-8"))

        self.writer.write(hdr)
        self.writer.write(body)

        self.encrypt_m.reset()
        return

    def __handle_read_data(self, action, byte_data):
        if action not in self.___acts:
            return

        if over_tcp.ACT_AUTH == action:
            ret = self.fn_auth_response(byte_data)
            if not ret:
                print("Authentication failed")
                self.delete_handler(self.fileno)
            return
        if over_tcp.ACT_CLOSE == action:
            print("the server require close")
            self.delete_handler(self.fileno)
            return
        if over_tcp.ACT_PONG == action:
            self.__is_sent_ping = False
            return
        if over_tcp.ACT_PING == action:
            self.__send_pong()
            return

        self.send_message_to_handler(self.fileno, self.__tun_fd, byte_data)

    def tcp_readable(self):
        self.set_timeout(self.fileno, self.__TIMEOUT)
        rdata = self.reader.read()
        self.__decrypt_m.add_data(rdata)

        while self.__decrypt_m.have_data():
            if not self.__decrypt_m.is_ok():
                return
            action = self.__decrypt_m.header_info()
            body_data = self.__decrypt_m.body_data()
            self.__decrypt_m.reset()
            self.__handle_read_data(action, body_data)

        return

    def tcp_writable(self):
        if not self.__is_sent_auth:
            ret_data = self.fn_auth_request()
            self.__send_auth(ret_data)
            return

        if self.writer.size() < 1:
            self.remove_evt_write(self.fileno)
            return

        self.set_timeout(self.fileno, self.__TIMEOUT)

        return

    def message_from_handler(self, from_fd, byte_data):
        # 没发送验证数据包就丢弃网卡的数据包
        if not self.__is_sent_auth:
            return
        # 防止内存过度消耗
        if self.writer.size() > self.__MAX_BUFFER_SIZE:
            return

        packet_length = (byte_data[2] << 8) | byte_data[3]
        self.encrypt_m.set_body_size(packet_length)
        hdr = self.encrypt_m.wrap_header(over_tcp.ACT_DATA)
        body = self.encrypt_m.wrap_body(byte_data)

        self.encrypt_m.reset()
        self.add_evt_write(self.fileno)
        self.writer.write(hdr)
        self.writer.write(body)

    def tcp_error(self):
        print("the system error")
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()
        print("the client exit")
        sys.exit(-1)

    def tcp_timeout(self):
        if self.__is_sent_ping:
            self.delete_handler(self.fileno)
            return
        self.__send_ping()

    @property
    def encrypt_m(self):
        return self.__encrypt_m

    @property
    def decrypt_m(self):
        return self.__decrypt_m

    def fn_auth_request(self):
        """
        :return dict:返回一个字典对象
        """
        pass

    def fn_auth_response(self, auth_resp_info):
        """验证响应之后调用该函数
        :param auth_resp_info:
        :return Boolean: True表示系统继续执行,False则表示停止执行
        """
        return True

    def set_virtual_ips(self, ips):
        """设置虚拟IP"""
        self.ctl_handler(self.fileno, self.__tun_fd, "set_virtual_ips", ips)
