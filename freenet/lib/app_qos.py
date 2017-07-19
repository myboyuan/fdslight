#!/usr/bin/env python3
"""应用层代理QOS保障
"""


class app_qos(object):
    __data = None

    def __init__(self):
        self.__data = {}

    def input(self, byte_data):
        cookie_id = (byte_data[0] << 8) | byte_data[1]

        if cookie_id not in self.__data:
            self.__data[cookie_id] = []

        pylist = self.__data[cookie_id]
        pylist.append(byte_data)

    def get_data(self):
        empty_list = []
        results = []

        for cookie_id in self.__data:
            pylist = self.__data[cookie_id]
            results.append(pylist.pop(0))
            if not pylist: empty_list.append(cookie_id)

        for cookie_id in empty_list:
            del self.__data[cookie_id]

        return results

    def reset(self):
        self.__data = {}

    def has_data(self):
        return bool(self.__data)
