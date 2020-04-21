#!/usr/bin/env python3
"""端口映射相关处理
"""


class port_map(object):
    __is_ipv6 = None

    __rules = None

    def __init__(self, is_ipv6=False):
        self.__rules = {}
        self.__is_ipv6 = is_ipv6

