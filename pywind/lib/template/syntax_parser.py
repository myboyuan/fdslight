#!/usr/bin/env python3
"""核心语法解析器,实现核心语法解析功能
"""


class SyntaxErr(Exception): pass


class ParserErr(Exception): pass


class _compile_line(object):
    """把每行待解析的字符串转换成Python数据结构
    """

    def __init__(self):
        pass

    def compile(self, line_sts):
        results = []

        rs1 = self.__parse1(line_sts)
        for is_pycode, sts in rs1:
            if not is_pycode:
                t = self.__parse2(sts)
                results += t
            else:
                results.append((is_pycode, sts,))
        return results

    def __parse1(self, line_sts):
        """解析百分号
        :param sts: 
        :return: 
        """
        pos = line_sts.find("%")

        if pos < 0: return [(False, line_sts,), ]

        s1 = line_sts[0:pos]
        pos += 1
        s2 = line_sts[pos:].lstrip()

        if not s1: return [(True, s2,)]

        return [(False, s1,), (True, s2,)]

    def __parse2(self, line_sts):
        """解析美元符号
        :param line_sts: 
        :return: 
        """
        results = []
        while 1:
            pos = line_sts.find("${")
            if pos < 0:
                results.append((False, line_sts,))
                break
            s1 = line_sts[0:pos]
            if s1: results.append((False, s1,))
            pos += 2
            line_sts = line_sts[pos:]
            pos = line_sts.find("}")
            if pos < 1: raise SyntaxErr
            s2 = line_sts[0:pos]
            results.append((True, s2,))
            pos += 1
            line_sts = line_sts[pos:]

        return results


class parser(object):
    __buff = None

    __parse_objects = None

    # 等待解析的FIFO队列
    __parse_fifo = None

    # 命名缓冲区,用于实现块功能
    __named_buff = None

    # 命名缓冲区函数
    __named_buff_functions = None

    # 普通函数
    __functions = None

    # 变量值
    __kwargs = None

    __compile_line = None

    def __init__(self):
        self.__buff = []
        self.__parse_objects = {}
        self.__parse_fifo = []
        self.__named_buff = {}
        self.__kwargs = {}
        self.__compile_line = _compile_line()

    def push_to_buff(self, sts):
        """把数据写入到缓冲区中
        :param sts: 
        :return: 
        """
        self.__buff.append(sts)

    def set_parse_object(self, objname, sts):
        """设置解析对象,一段字符串代表一个解析对象
        :param objname:对象名,可以任意命名
        :param sts: 
        :return: 
        """
        self.__parse_fifo.append(sts)
        self.__parse_objects[objname] = sts

    def compile(self, objname):
        """把解析的字符串转换成Python数据结构
        :return: 
        """
        if objname not in self.__parse_objects: raise ParserErr("cannot found compile object '%s'" % objname)
        sts = self.__parse_objects[objname]

        tmplist = sts.split("\n")




    def register_named_buff_func(self, funcname):
        """注册命名缓冲区函数
        :param funcname: 
        :return: 
        """
        pass

    def register_func(self, funcname):
        """注册普通函数
        :param funcname: 
        :return: 
        """
        pass


cls = _compile_line()
print(cls.compile("${name} hello,world ${myfunc(name)}%for name in hello:print()"))
