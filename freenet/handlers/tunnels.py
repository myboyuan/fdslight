#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket, time
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.logging as logging


class tcp_tunnel(tcp_handler.tcp_handler):
    __crypto = None
    __crypto_configs = None
    __conn_timeout = None

    def init_func(self, creator, address, crypto, crypto_configs, conn_timeout=800, is_ipv6=False):
        self.__crypto_configs = crypto_configs
        self.__crypto = crypto
        self.__conn_timeout = conn_timeout

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

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(
                    self.fileno, _tcp_tunnel_handler, self.__crypto,
                    self.__crypto_configs, cs, address, self.__conn_timeout
                )
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _tcp_tunnel_handler(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None
    __address = None

    __update_time = 0
    __conn_timeout = 0

    __LOOP_TIMEOUT = 10

    __session_id = None

    def init_func(self, creator, crypto, crypto_configs, cs, address, conn_timeout):
        self.__address = address
        self.__conn_timeout = conn_timeout
        self.__update_time = time.time()
        self.__session_id = None

        self.set_socket(cs)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        logging.print_general("tcp_connect", address)

        return self.fileno

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__decrypt.input(rdata)

        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except proto_utils.ProtoError:
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.__decrypt.get_pkt()
                if not pkt_info: break
                session_id, action, message = pkt_info

                if self.__session_id and self.__session_id != session_id:
                    print("----")
                    self.delete_handler(self.fileno)
                    return

                self.__session_id = session_id
                self.dispatcher.handle_msg_from_tunnel(self.fileno, session_id, self.__address, action, message)
            ''''''
        return

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        if self.__session_id:
            self.dispatcher.tell_del_all_app_proxy(self.__session_id)

        self.unregister(self.fileno)
        self.close()
        logging.print_general("tcp_disconnect", self.__address)

    def send_msg(self, session_id, address, action, message):
        sent_pkt = self.__encrypt.build_packet(session_id, action, message)
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)
        self.__encrypt.reset()
        self.__update_time = time.time()


class udp_tunnel(udp_handler.udp_handler):
    def init_func(self, creator, address, crypto, crypto_configs, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        return self.fileno

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result
        self.dispatcher.handle_msg_from_tunnel(self.fileno, session_id, address, action, byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, session_id, address, action, message):
        ippkts = self.__encrypt.build_packets(session_id, action, message)
        self.__encrypt.reset()

        for ippkt in ippkts: self.sendto(ippkt, address)

        self.add_evt_write(self.fileno)
