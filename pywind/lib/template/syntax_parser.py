#!/usr/bin/env python3
"""核心语法解析器,实现核心语法解析功能
"""


def get_syntax_block(sts):
    """获取语法块
    :param line: 
    :return: 
    """
    pass


def get_func_block(line):
    """获取函数块
    :param line: 
    :return: 
    """
    pass


class parser(object):
    __buff = None

    def __init__(self):
        self.__buff = []

    def push_to_buff(self, sts):
        """把数据写入到缓冲区中
        :param sts: 
        :return: 
        """
        self.__buff.append(sts)