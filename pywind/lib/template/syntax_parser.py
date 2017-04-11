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


def parse(sts):
    compile_line = _compile_line()
    tmplist = sts.split("\n")
    n = 1

    results = []
    for line_sts in tmplist:
        try:
            results += compile_line.compile(line_sts)
        except SyntaxErr:
            return (False, n, line_sts,)
        n += 1

    return (True, results,)
