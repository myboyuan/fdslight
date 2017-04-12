#!/usr/bin/env python3
"""核心语法执行器"""

import pywind.lib.tpl_syntax.syntax_parser as syntax_parser


class ExecuteErr(Exception): pass


class execute(object):
    __kwargs = None

    __ext_attrs = None

    # 缓冲区
    __buff = None

    # 保存block标签的相关信息
    block_map = None

    __parser = None

    __syntax_tree = None

    def __init__(self, **kwargs):
        self.__kwargs = kwargs

        self.__ext_attrs = {}
        self.__buff = []
        self.__parser = syntax_parser.parser()

        self.__syntax_tree = []

    @property
    def kwargs(self):
        return self.__kwargs

    def register_ext_attr(self, funcname, funcobj):
        """注册扩展函数
        :param funcname:字符串函数名 
        :param funcobj: 函数对象
        :return: 
        """
        self.__ext_attrs[funcname] = funcobj

    def unregister_ext_attr(self, funcname):
        """删除扩展函数
        :param funcname:函数名 
        :return: 
        """
        pydict = self.__ext_attrs

        if funcname not in pydict: return
        del pydict[funcname]

    def put_to_buff(self, content):
        self.__buff.append(content)

    def __check_sec(self, code_text):
        filters = ("eval", "exec", "import", "open")
        for s in filters:
            p = code_text.find(s)
            if p > -1: raise ExecuteErr("dangerous attr or keyword '%s'" % code_text)
        return

    def __exe_pycode(self, code_text):
        self.__check_sec(code_text)
        exec(code_text, locals())

    def __exe_pysyntax(self, code_text):
        self.__check_sec(code_text)

        return eval(code_text, locals())

    def __exe_from_syntax_tree(self, syntax_tree):
        for flags, v in syntax_tree:
            if flags == syntax_parser.TYPE_TEXT:
                self.__buff.append(v)
                continue
            if flags == syntax_parser.TYPE_PYSYNTAX:
                self.__buff.append(self.__exe_pysyntax(v))
                continue
            if flags == syntax_parser.TYPE_BLOCK:
                self.__exe_from_syntax_tree(self.block_map[v])
                continue
            self.__exe_pycode(v)

    def _gen_syntax_tree(self, sts):
        syntax_tree, block_map = self.__parser.parse(sts)
        self.block_map = block_map
        self.__syntax_tree = syntax_tree

    def _exe(self):
        self.__exe_from_syntax_tree(self.__syntax_tree)

    def __getattr__(self, item):
        if item == "V": return self.__kwargs
        if item == "show":
            return self.__show

        if item not in self.__ext_attrs:
            raise ExecuteErr("cannot found property or attr '%s'" % item)

        return self.__ext_attrs[item]

    def _get_buff_content(self):
        t = []
        for v in self.__buff: t.append(str(v))

        self.__buff = []

        return "".join(t)

    def __show(self, sts):
        self.__buff.append(sts)
