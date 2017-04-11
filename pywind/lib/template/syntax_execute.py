#!/usr/bin/env python3
"""语法执行器"""


class execute(object):
    def register_ext_function(self, funcname, funcobj, is_block_func=False):
        """注册扩展函数
        :param funcname:字符串函数名 
        :param funcobj: 函数对象
        :param is_block_func:是否是块函数
        :return: 
        """
        pass

    def unregister_ext_function(self, funcname, is_block_func=False):
        """删除扩展函数
        :param funcname:函数名 
        :param is_block_func:是否是块函数 
        :return: 
        """
        pass

    def set_exe_object(self, name, value):
        """设置执行对象
        :param name: 
        :param value: 
        :return: 
        """
        pass


