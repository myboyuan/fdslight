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

    def ws_init(self):
        self.__any2tcp_fileno = -1

    def ws_readable(self, message, fin, rsv, opcode, frame_finish):
        if opcode == wslib.OP_CLOSE:
            self.ws_close()
            return

    def ws_release(self):
        pass
