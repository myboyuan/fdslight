#!/usr/bin/env python3
"""语法执行器"""

import pywind.lib.template.syntax_parser as syntax_parser


class ExecuteErr(Exception): pass


class execute(object):
    __exe_objects = None

    __kwargs = None

    __ext_block_functions = None
    __ext_functions = None

    # 运行步骤1
    __run_step1 = None

    # 结果缓冲区
    __buff = None

    def __init__(self):
        self.__exe_objects = {}
        self.__kwargs = {}

        self.__ext_block_functions = {}
        self.__ext_functions = {}
        self.__run_step1 = []
        self.__buff = []

    def register_ext_function(self, funcname, funcobj, is_block_func=False):
        """注册扩展函数
        :param funcname:字符串函数名 
        :param funcobj: 函数对象
        :param is_block_func:是否是块函数
        :return: 
        """
        if is_block_func:
            self.__ext_block_functions[funcname] = funcobj
        else:
            self.__ext_functions[funcname] = funcobj

        return

    def unregister_ext_function(self, funcname, is_block_func=False):
        """删除扩展函数
        :param funcname:函数名 
        :param is_block_func:是否是块函数 
        :return: 
        """
        if is_block_func:
            pydict = self.__ext_block_functions
        else:
            pydict = self.__ext_functions

        if funcname not in pydict: return
        del pydict[funcname]

    def set_exe_object(self, name, value):
        """设置执行对象
        :param name: 
        :param value: 
        :return: 
        """
        self.__exe_objects[name] = value

    def put_to_buff(self, content):
        self.__buff.append(content)

    def exe(self, name):
        if name not in self.__exe_objects: raise ExecuteErr("cannot found execute object '%s'" % name)

        sts = self.__exe_objects[name]
        cls = syntax_parser.parser()

        rs = cls.parse(sts)

        print(rs)

    def __getattr__(self, item):
        pass


fd = open("./syntax.txt", "r")

exe = execute()
exe.set_exe_object("test", fd.read())
fd.close()

exe.exe("test")
