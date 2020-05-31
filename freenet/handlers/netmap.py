#!/usr/bin/env python3

import pywind.evtframework.handlers.handler as handler


class nm_handler(handler.handler):
    def init_func(self, creator_fd, fd):
        """
        :param creator_fd:
        :param fd:
        :return:
        """
        self.set_fileno(fd)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    @property
    def gw(self):
        return self.dispatcher.gw

    def evt_read(self):
        rs = self.gw.nm_handle_for_read(100)

    def evt_write(self):
        rs = self.gw.nm_handle_for_write()

    def delete(self):
        self.unregister(self.fileno)

    def error(self):
        pass
