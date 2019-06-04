#!/usr/bin/env python3
import pywind.web.handlers.websocket as websocket

class ws_listener(websocket.ws_listener):
    def ws_accept(self, cs, caddr):
        self.create_handler(ws_listener, cs, caddr)

    def ws_release(self):
        pass


class ws_handler(websocket.ws_handler):
    def ws_init(self):
        pass

    def ws_readable(self, message, fin, rsv, opcode, frame_finish):
        pass

    def ws_release(self):
        pass
