#!/usr/bin/env python3

import pywind.evtframework.handlers.handler as handler


class nm_handler(handler.handler):
    def init_func(self, creator_fd, if_name):
        """
        :param creator_fd:
        :param if_name:
        :return:
        """
        pass

    def evt_read(self):
        pass

    def evt_write(self):
        pass

    def delete(self):
        pass

    def error(self):
        pass
