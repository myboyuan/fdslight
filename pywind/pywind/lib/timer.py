#!/usr/bin/env python3

import time


class timer(object):
    # fmt:{sock_name1:[start_time,timeout],...}
    __timeout_info = {}
    # {future_seconds1:name1,future_seconds_seconds2:name2,...}
    __timeout_flags = {}
    # convenient for checking if timeout
    __timeout_list = []
    __is_sort = False

    def __init__(self):
        self.__timeout_info = {}
        self.__timeout_flags = {}
        self.__timeout_list = []
        self.__is_sort = False

    def get_timeout_names(self):
        """
        Note:
            this function will delete element from self.__timeout_list and self.__timeout_flags
        """
        current = time.time()
        current = int(current)

        if not self.__is_sort:
            self.__timeout_list.sort()
            self.__is_sort = True
        ''''''
        names = []

        while 1:
            try:
                t = self.__timeout_list.pop(0)

            except IndexError:
                return names

            if t in self.__timeout_flags:
                if t > current:
                    self.__timeout_list.append(t)
                    return names

                for name in self.__timeout_flags[t]:
                    if name in self.__timeout_info:
                        names.append(name)
                    ''''''
                ''''''
                del self.__timeout_flags[t]
            """"""
        return names


    def set_timeout(self, name, seconds=0):
        self.__is_sort = False
        old_info = None

        if name in self.__timeout_info:
            seconds = self.__timeout_info[name][1]
            old_info = self.__timeout_info[name]

        new_set = [int(time.time()), seconds]
        self.__timeout_info[name] = new_set

        if old_info != None:
            timeout_time = old_info[0] + old_info[1]
        else:
            timeout_time = 0

        if timeout_time in self.__timeout_flags:
            try:
                self.__timeout_flags[timeout_time].remove(name)
            except ValueError:
                pass

        timeout_time = new_set[0] + new_set[1]

        if timeout_time not in self.__timeout_flags:
            self.__timeout_flags[timeout_time] = []

        self.__timeout_flags[timeout_time].append(name)
        self.__timeout_list.append(timeout_time)

        return


    def exists(self, name):
        return (name in self.__timeout_info)


    def drop(self, name):
        del self.__timeout_info[name]


    def get_min_time(self):
        if not self.__is_sort:
            self.__timeout_list.sort()
            self.__is_sort = True

        try:
            return self.__timeout_list[0]-int(time.time())
        except IndexError:
            return 0
        ''''''





