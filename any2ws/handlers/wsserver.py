#!/usr/bin/env python3
import pywind.web.handlers.websocket as websocket
import pywind.web.lib.websocket as wslib
import any2ws.handlers.any2tcp as any2tcp


class ws_listener(websocket.ws_listener):
    def ws_accept(self, cs, caddr):
        self.create_handler(-1, ws_handler, cs, caddr)

    def ws_release(self):
        pass


class ws_handler(websocket.ws_handler):
    __any2tcp_fileno = None

    def ws_init(self):
        self.__any2tcp_fileno = -1

        print("connected %s:%s" % self.caddr)

        remote_cfgs = self.configs["remote"]
        enable_ipv6 = bool(int(remote_cfgs.get("enable_ipv6", 0)))
        host = remote_cfgs["host"]
        port = int(remote_cfgs["port"])
        conn_timeout = int(remote_cfgs.get("conn_timeout", 600))

        """
        self.__any2tcp_fileno = self.create_handler(self.fileno, any2tcp.client, (host, port,), is_ipv6=enable_ipv6,
                                                    conn_timeout=conn_timeout)
                                                    """
        self.set_ws_timeout(conn_timeout + 30)

    def ws_readable(self, message, fin, rsv, opcode, frame_finish):
        if opcode != wslib.OP_BIN:
            self.delete_handler(self.fileno)
            return

        if self.__any2tcp_fileno < 0:
            self.delete_handler(self.fileno)
            return

        self.send_message_to_handler(self.fileno, self.__any2tcp_fileno, message)

    def ws_release(self):
        print("disconnect %s:%s" % self.caddr)

    @property
    def configs(self):
        return self.dispatcher.configs

    def tcp_delete(self):
        if self.__any2tcp_fileno > 0:
            self.delete_handler(self.__any2tcp_fileno)
            self.__any2tcp_fileno = -1
        super().tcp_delete()

    def tell_any2tcp_delete(self):
        self.__any2tcp_fileno = -1
        self.delete_this_no_sent_data()

    def on_handshake(self, request, headers):
        value = self.get_header_value("x-auth-id", headers)

        if not value:
            return False

        auth_id = self.configs["local"]["auth_id"]
        print(auth_id == value)

        return auth_id == value

    def get_header_value(self, name, headers):
        for k, v in headers:
            if name.lower() == k.lower():
                return v
            ''''''
        return None
