#!/usr/bin/env python3

import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.handlers.socks5 as socks5_handlers


class socks5server(dispatcher.dispatcher):
    __configs = None

    def __init__(self):
        super(socks5server, self).__init__()

    def debug_run(self):
        self.create_poll()

        fd = self.create_handler(
            -1, socks5_handlers.sserverd,
            ("127.0.0.1", 8000)
        )

        self.get_handler(fd).after()

    def init_func(self):
        self.debug_run()


app = socks5server()
app.ioloop()
