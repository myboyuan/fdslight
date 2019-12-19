#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import time, socket


class client(tcp_handler.tcp_handler):
    __creator = None
    __session_id = None
    __auth_id = None
    __wait_sent = None

    def init_func(self, creator_fd, address, auth_id, session_id, is_ipv6=False):
        self.__creator = creator_fd
        self.__session_id = session_id
        self.__auth_id = auth_id
        self.__wait_sent = []

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

    def tcp_readable(self):
        rdata = self.reader.read()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.dispatcher.tell_delete(self.__session_id)
        self.unregister(self.fileno)

    def send_data(self, byte_data):
        if not self.is_conn_ok():
            self.__wait_sent.append(byte_data)
            return

        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)

    def message_from_handler(self, from_fd, byte_data):
        self.send_data(byte_data)
