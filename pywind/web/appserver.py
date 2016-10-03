#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.web.handler.scgi as scgi


class appserver(dispatcher.dispatcher):
    __configs = None

    def __init__(self, configs):
        super(appserver, self).__init__()
        self.__configs = configs

    def debug_run(self):
        self.create_poll()
        fd = self.create_handler(-1, scgi.scgid_listen, self.__configs)
        self.get_handler(fd).after()

    def init_func(self):
        self.debug_run()
