#!/usr/bin/env python3
"""
import dns.resolver

r = dns.resolver.Resolver()
r.nameservers = ["192.168.1.100", ]

for qss in r.query("www.google.com"):
    print(qss)
"""
"""
fdst = open("./fdslight_etc/blacklist.txt", "rb")
results = []

for line in fdst:
    if line[0] == ord('#'):
        results.append(line)
        continue
    line=line.replace(b"\r",b'')
    line=line.replace(b"\n",b'')
    if not line:
        results.append(b"\r\n")
        continue
    nline = b"".join((line,b":1\r\n",))
    results.append(nline)

fdst.close()
fdst=open("./blacklist.txt","wb")
for line in results:fdst.write(line)
fdst.close()
"""


class _host_match(object):
    """对域名进行匹配,以找到是否在符合的规则列表中
    """
    __rules = None

    def __init__(self):
        self.__rules = {}

    def add_rule(self, host_rule):
        host, flags = host_rule
        tmplist = host.split(".")
        tmplist.reverse()

        if not tmplist:
            return

        lsize = len(tmplist)
        n = 0
        tmpdict = self.__rules

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

        tmpdict = self.__rules
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

    def print_dict(self):
        print(self.__rules)


import freenet.lib.file_parser as file_parser

h = _host_match()
rules = file_parser.parse_host_file("fdslight_etc/blacklist.txt")

for rule in rules: h.add_rule(rule)

h.print_dict()
print(h.match("googledrive.com"))
