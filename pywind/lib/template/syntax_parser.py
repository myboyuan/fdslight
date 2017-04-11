#!/usr/bin/env python3
"""核心语法解析器,实现核心语法解析功能
"""

### 表示从何种语法标志获取解析结果的
# 没有任何语法标志
SYNTAX_FLAG_NONE = 0

# 从<%block name=''>解析而来
SYNTAX_FLAG_BLOCK_BEGIN = 1
# 从<%block name=''/>解析而来
SYNTAX_FLAG_BLOCK_BEGIN_AND_END = 2

# 从</%block>解析而来
SYNTAX_FLAG_BLOCK_END = 3

# 从百分号解析得来的
SYNTAX_FLAG_PER = 4

# 从美元符号解析得来的
SYNTAX_FLAG_DOL = 5


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
        rs2 = []
        for flag, sts in rs1:
            if flag == SYNTAX_FLAG_NONE:
                t = self.__parse2(sts)
                rs2 += t
            else:
                rs2.append((flag, sts,))
        for flag, sts in rs2:
            if flag == SYNTAX_FLAG_NONE:
                t = self.__parse3(sts)
                results += t
            else:
                results.append((flag, sts,))
        return results

    def __parse1(self, line_sts):
        """解析<%block>
        :param line_sts: 
        :return: 
        """
        results = []
        tmp_results = []

        # 解析block开始标签或者开始和结束标签连在一起的标签
        while 1:
            pos = line_sts.find("<%block")
            if pos < 0:
                tmp_results.append((SYNTAX_FLAG_NONE, line_sts,))
                break
            t = line_sts[pos:].find(">")
            if t < 8: raise SyntaxError
            t -= 1
            if line_sts[t] == "/":
                flag = SYNTAX_FLAG_BLOCK_BEGIN_AND_END
            else:
                flag = SYNTAX_FLAG_BLOCK_BEGIN
            t += 2
            s1 = line_sts[0:pos]
            if s1: tmp_results.append((SYNTAX_FLAG_NONE, s1,))
            s2 = line_sts[pos:t]
            tmp_results.append((flag, s2))
            line_sts = line_sts[t:]

        # 解析block结束标签
        for flag, sts in tmp_results:
            if flag != SYNTAX_FLAG_NONE:
                results.append((flag, sts,))
                continue
            while 1:
                pos = sts.find("</%block>")
                if pos < 0:
                    results.append((flag, sts))
                    break
                s1 = sts[0:pos]
                pos += 9
                sts = sts[pos:]
                if s1: results.append((flag, s1,))
                results.append((SYNTAX_FLAG_BLOCK_END, "</%block>"))
            ''''''

        return results

    def __parse2(self, line_sts):
        """解析百分号
        :param sts: 
        :return: 
        """
        pos = line_sts.find("%")

        if pos < 0: return [(SYNTAX_FLAG_NONE, line_sts,), ]

        s1 = line_sts[0:pos]
        pos += 1
        s2 = line_sts[pos:].lstrip()

        if not s1: return [(SYNTAX_FLAG_PER, s2,)]

        return [(SYNTAX_FLAG_NONE, s1,), (SYNTAX_FLAG_PER, s2,)]

    def __parse3(self, line_sts):
        """解析美元符号
        :param line_sts: 
        :return: 
        """
        results = []
        while 1:
            pos = line_sts.find("${")
            if pos < 0:
                results.append((SYNTAX_FLAG_NONE, line_sts,))
                break
            s1 = line_sts[0:pos]
            if s1: results.append((SYNTAX_FLAG_NONE, s1,))
            pos += 2
            line_sts = line_sts[pos:]
            pos = line_sts.find("}")
            if pos < 1: raise SyntaxErr
            s2 = line_sts[0:pos]
            results.append((SYNTAX_FLAG_DOL, s2,))
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


def _parse_tpl_block_block(data_struct):
    """解析模版block标签
    :param data_struct: 
    :return: 
    """
    __block_begin = []
    __block_end = []

    # 首先进行数据扫描
    n = 0
    for flag, sts in data_struct:
        if flag not in (SYNTAX_FLAG_BLOCK_BEGIN, SYNTAX_FLAG_BLOCK_END):
            n += 1
            continue
        if SYNTAX_FLAG_BLOCK_BEGIN == flag: __block_begin.append(n)
        if SYNTAX_FLAG_BLOCK_END == flag: __block_end.append(n)
        n += 1




class parser(object):
    pass
