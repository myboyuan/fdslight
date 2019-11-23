#!/usr/bin/env python3

class host_match(object):
    """对域名进行匹配,以找到是否在符合的规则列表中
    """
    __domain_rules = None

    __ip_rules = None
    __ipv6_rules = None

    def __init__(self):
        self.__domain_rules = {}
        self.__ip_rules = {}
        self.__ipv6_rules = {}

    def add_ip_rule(self, rule):
        pass

    def add_rule(self, host_rule):
        host, flags = host_rule
        tmplist = host.split(".")
        tmplist.reverse()

        if not tmplist: return

        lsize = len(tmplist)
        n = 0
        tmpdict = self.__domain_rules

        old_name = ""
        old_dict = tmpdict
        while n < lsize:
            name = tmplist[n]
            if name not in tmpdict:
                if name == "*" or n == lsize - 1:
                    old_dict[old_name] = {name: flags}
                    break
                old_dict = tmpdict
                tmpdict[name] = {}
            if name == "*":
                n += 1
                continue
            old_name = name
            tmpdict = tmpdict[name]
            n += 1

        return

    def match(self, host):
        tmplist = host.split(".")
        tmplist.reverse()
        # 加一个空数据，用以匹配 xxx.xx这样的域名
        tmplist.append("")

        is_match = False
        flags = 0

        tmpdict = self.__domain_rules
        for name in tmplist:
            if "*" in tmpdict:
                is_match = True
                flags = tmpdict["*"]
                break
            if name not in tmpdict: break
            v = tmpdict[name]
            if type(v) != dict:
                is_match = True
                flags = v
                break
            tmpdict = v

        return (is_match, flags,)

    def clear(self):
        self.__domain_rules = {}
        self.__ip_rules = {}
        self.__ipv6_rules = {}

    def match_ipaddr(self, ipaddr, is_ipv6=False):
        pass
