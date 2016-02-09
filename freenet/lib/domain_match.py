#!/usr/bin/env python3
"""
实现域名匹配
"""


class domain_match(object):
    # 格式示例如下
    # {"com":{"google":"*"}),
    __rules = None

    def __init__(self):
        self.__rules = {}

    def add_rule(self, host):
        tmp_list = host.split(".")
        tmp_list.reverse()

        try:
            first = tmp_list.pop(0)
        except IndexError:
            return

        if first not in self.__rules: self.__rules[first] = {}
        tmp_dict = self.__rules[first]
        old_name = first
        old_tmp_dict = tmp_dict

        for name in tmp_list:
            if name == "*":
                old_tmp_dict[old_name] = "*"
                break
            if name not in tmp_dict:
                old_tmp_dict = tmp_dict
                tmp_dict[name] = {}
                tmp_dict = tmp_dict[name]
            old_name = name
        return

    def is_match(self, host):
        """
        :param host:
        :return Boolean: True表示匹配成功,False表示匹配失败
        """
        tmp_list = host.split(".")
        tmp_list.reverse()
        is_match = False

        try:
            first = tmp_list.pop(0)
        except IndexError:
            return is_match

        if first not in self.__rules:
            return is_match

        tmp_dict = self.__rules[first]

        for name in tmp_list:
            if name not in tmp_dict:
                break
            tmp_dict = tmp_dict[name]
            if tmp_dict == "*":
                is_match = True
                break

            if tmp_dict == {}:
                is_match = True
                break

        return is_match

