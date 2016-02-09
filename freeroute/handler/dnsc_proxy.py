#!/usr/bin/env python3
import pywind.evtframework.handler.udp_handler as udp_handler
import socket


class dnsc_proxy(udp_handler.udp_handler):
    __dns_server_address = None
    __creator_fd = -1

    def init_func(self, creator_fd, dns_server):
        self.__dns_server_address = (dns_server, 53)
        self.__creator_fd = creator_fd

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(self.__dns_server_address)
        self.set_socket(s)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return s.fileno()

    def message_from_handler(self, from_fd, byte_data):
        self.add_evt_write(self.fileno)
        self.sendto(byte_data, self.__dns_server_address)

    def udp_readable(self, message, address):
        self.send_message_to_handler(self.fileno, self.__creator_fd, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        pass

    def udp_error(self):
        pass

    def udp_delete(self):
        pass
