#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.web.handler.scgi as scgi
from pywind.global_vars import global_vars

class webserver(dispatcher.dispatcher):
    def init_func(self, config):
        # global_vars["pywind.fastcgi.current_conns"] = 0
        self.__debug_run(config)

    def init_func_after_fork(self):
        self.create_poll()

    def __debug_run(self, config):
        self.create_poll()
        f_no = self.create_handler(-1, scgi.scgi_server, config)
        self.get_handler(f_no).after()

    def __run(self):
        pass


def main():
    import pywind.web.etc.app_sample as config
    wservice = webserver()
    wservice.ioloop(config.configs)


if __name__ == "__main__":
    main()
