#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.handlers.socks5c as socks5c

class appserver(dispatcher.dispatcher):
    __configs = None

    def __init__(self):
        super(appserver, self).__init__()

    def debug_run(self):
        self.create_poll()
        fd = self.create_handler(-1, socks5c.sserverd,("127.0.0.1",8000),())
        self.get_handler(fd).after()

    def init_func(self):
        self.debug_run()


app = appserver()
app.ioloop()