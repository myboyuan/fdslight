#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.p_rpc.handler.p_rpcd as p_rpcd


class rpcd(dispatcher.dispatcher):
    __functions = None
    __listen_address = None

    def debug_run(self):
        self.create_poll()
        fd = self.create_handler(-1, p_rpcd.rpcd, self.__functions, self.__listen_address)
        self.get_handler(fd).after()

    def init_func(self, functions, address):
        self.__functions = functions
        self.__listen_address = address
        self.debug_run()


def sayHello(x,y):
    return x+y


functions = {
    "::": [("sayHello", sayHello), ]
}

app = rpcd()
app.ioloop(functions, ("127.0.0.1", 8600))
