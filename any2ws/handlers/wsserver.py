#!/usr/bin/env python3
import pywind.web.handlers.websocket as websocket
import pywind.web.lib.websocket as wslib
import any2ws.handlers.any2tcp as any2tcp


class ws_listener(websocket.ws_listener):
    def ws_accept(self, cs, caddr):
        self.create_handler(ws_listener, cs, caddr)

    def ws_release(self):
        pass


class ws_handler(websocket.ws_handler):
    __any2tcp_fileno = None
    __is_delete = None

    def ws_init(self):
        self.__is_delete = False
        self.__any2tcp_fileno = -1

        print("connection")

        remote_cfgs = self.configs["remote"]
        enable_ipv6 = bool(int(remote_cfgs.get("enable_ipv6", 0)))
        host = remote_cfgs["host"]
        port = int(remote_cfgs["port"])
        conn_timeout = int(remote_cfgs.get("conn_timeout", 600))

        """
        self.__any2tcp_fileno = self.create_handler(self.fileno, any2tcp.client, (host, port,), is_ipv6=enable_ipv6,
                                                    conn_timeout=conn_timeout)
                                                    """
        self.set_ws_timeout(conn_timeout + 60)

    def ws_readable(self, message, fin, rsv, opcode, frame_finish):
        if opcode != wslib.OP_BIN:
            self.delete_handler(self.fileno)
            return

        print(message)

        if self.__any2tcp_fileno < 0:
            self.delete_handler(self.fileno)
            return

        self.send_message_to_handler(self.fileno, self.__any2tcp_fileno, message)

    def ws_release(self):
        pass

    @property
    def configs(self):
        return self.dispatcher.configs

    def tcp_delete(self):
        if self.__is_delete: return
        self.__is_delete = True
        if self.__any2tcp_fileno > 0:
            self.delete_handler(self.__any2tcp_fileno)
            self.__any2tcp_fileno = -1
        super().tcp_delete()

    def tell_any2tcp_delete(self):
        if self.__is_delete: return
        self.delete_handler(self.fileno)
