#!/usr/bin/env python3
import socket, time
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import any2ws.handlers.wsclient as wsclient


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

        return self.fileno

    def after(self, *args, **kwargs):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(self.fileno, listener_handler, cs, address)
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class listener_handler(tcp_handler.tcp_handler):
    __caddr = None
    __wsc_fileno = None
    __tell_flags = None

    def init_func(self, creator_fd, cs, caddr):
        self.__caddr = caddr
        self.__wsc_fileno = -1
        self.__tell_flags = False

        self.set_socket(cs)
        self.create_wsclient()
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def create_wsclient(self):
        remote = self.configs

        host = remote["host"]
        port = int(remote.get("port", 80))
        ssl_on = bool(int(remote.get("ssl_on", 0)))
        enable_ipv6 = bool(int(remote.get("enable_ipv6", 0)))
        conn_timeout = int(remote.get("conn_timeout", 480))
        url = remote["url"]
        auth_id = remote["auth_id"]

        fileno = self.create_handler(self.fileno, wsclient.wsclient, (host, port,), url, auth_id, is_ipv6=enable_ipv6,
                                     ssl_on=ssl_on, conn_timeout=conn_timeout)
        self.__wsc_fileno = fileno

    def tcp_readable(self):
        rdata = self.reader.read()
        if not self.handler_exists(self.__wsc_fileno): return
        self.send_message_to_handler(self.fileno, self.__wsc_fileno, rdata)

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        print("any2tcp connection closed")

        if self.__wsc_fileno > 0 and not self.__tell_flags:
            self.delete_handler(self.__wsc_fileno)
            self.__wsc_fileno = -1

        self.unregister(self.fileno)
        self.close()

    @property
    def configs(self):
        return self.dispatcher.configs["remote"]

    def tell_ws_delete(self):
        self.__wsc_fileno = -1
        if self.writer.size() == 0:
            self.delete_handler(self.fileno)
            return
        self.delete_this_no_sent_data()

    def message_from_handler(self, from_fd, byte_data):
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)


class client(tcp_handler.tcp_handler):
    __address = None
    __creator = None
    __wait_writes = None
    __conn_timeout = None

    def init_func(self, creator_fd, address, conn_timeout=600, is_ipv6=False):
        self.__ws_conn_fileno = -1
        self.__creator = creator_fd
        self.__wait_writes = []
        self.__conn_timeout = conn_timeout

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

        if not self.__wait_writes:
            self.writer.write(b"".join(self.__wait_writes))
            self.add_evt_write(self.fileno)
            self.__wait_writes = []
        self.__up_time = time.time()

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__up_time = time.time()
        self.send_message_to_handler(self.fileno, self.__creator, rdata)

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

        t = time.time()
        if t - self.__up_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        self.dispatcher.get_handler(self.__creator).tell_any2tcp_delete()
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, byte_data):
        if from_fd != self.__creator: return
        if not self.is_conn_ok():
            self.__wait_writes.append(byte_data)
        else:
            self.writer.write(byte_data)
            self.add_evt_write(self.fileno)
