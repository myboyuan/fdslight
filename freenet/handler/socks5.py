#!/usr/bin/env python3

import pywind.evtframework.handler.tcp_handler as tcp_handler
import socket


class tcp_client(tcp_handler.tcp_handler):
    __TIMEOUT = 600

    def init_func(self, creator, address, is_ipv6=False):
        if not is_ipv6:
            s = socket.socket()
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(address, 8)

    def connect_ok(self):
        pass

    def tcp_timeout(self):
        self.delete_handler(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        pass



class socks5_listen(tcp_handler.tcp_handler):
    __is_ipv6 = None

    def init_func(self, creator, address, is_ipv6=False):
        if not is_ipv6:
            s = socket.socket()
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.set_socket(s)
        self.__is_ipv6 = is_ipv6
        self.bind(address)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(self.fileno, cs, address, is_ipv6=self.__is_ipv6)
            except BlockingIOError:
                break

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class socks5_server_handler(tcp_handler.tcp_handler):
    __caddr = None
    __TIMEOUT = 600
    __step = 1

    def __get_address(self, byte_data):
        seq = []
        ok = False

        cnt = 1
        for n in byte_data:
            if n == 0:
                ok = True
                break
            cnt += 1
            seq.append(n)

        return (ok, bytes(seq), cnt,)

    def __handle_step1(self):
        if self.reader.size() < 3: return

        byte_data = self.reader.read(3)
        version = byte_data[0]

        if version != 5:
            self.delete_handler(self.fileno)
            return
        methods = byte_data[1]
        method = byte_data[2]

        self.add_evt_write(self.fileno)

        if method != 0:
            self.writer.write(bytes([5, 0xff, ]))
            self.delete_this_no_sent_data(self.fileno)
            return
        self.writer.write(bytes([5, 0]))
        self.__step = 2

    def __handle_step2(self):
        if self.reader.size() < 7:
            self.delete_handler(self.fileno)
            return

        byte_data = self.reader.read()
        version = byte_data[0]
        if version != 5:
            self.delete_handler(self.fileno)
            return
        cmd = byte_data[1]
        if cmd not in (1, 2, 3,):
            pass
        atyp = byte_data[3]
        if atyp not in (1, 3, 4,):
            pass

        ok, dst_addr, cnt = self.__get_address(byte_data[4:])

        if not ok:
            pass

        a = cnt
        b = cnt + 1

        try:
            dst_port = (byte_data[a] << 8) | byte_data[b]
        except IndexError:
            self.delete_handler(self.fileno)
            return

    def __handle_step3(self):
        pass

    def init_func(self, creator, cs, address, is_ipv6=False):
        self.__caddr = address
        self.__step = 1

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_readable(self):
        if self.__step == 1: self.__handle_step1()
        if self.__step == 2: self.__handle_step2()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self,from_fd,cmd,*args,**kwargs):
        if cmd not in ("connect_ok","connect_failed",):
            return False

        return True