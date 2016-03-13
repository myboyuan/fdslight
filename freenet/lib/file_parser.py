#!/usr/bin/env python3
"""文件解析器,对dns分发的rules和白名单ip列表进行解析
文件格式:一条规则就是一行,#开头的表示注解:
"""

import socket


class FilefmtErr(Exception): pass


def __drop_comment(line):
    """删除注释"""
    pos = line.find("#")
    if pos < 0:
        return line
    return line[0:pos]


def __read_from_file(fpath):
    result = []
    fdst = open(fpath, "r")

    for line in fdst:
        line = __drop_comment(line)
        line = line.replace("\r", "")
        line = line.replace("\n", "")
        line = line.lstrip()
        line = line.rstrip()
        if not line: continue
        result.append(line)
    fdst.close()

    return result


def parse_host_file(fpath):
    """解析主机文件,即域名规则文件"""
    lines = __read_from_file(fpath)
    return lines


def __get_ip_subnet(line):
    """检查子网格式是否正确"""
    pos = line.find("/")
    if pos < 7: return None
    ipaddr = line[0:pos]
    pos += 1

    try:
        ip_packet = socket.inet_aton(ipaddr)
        mask = int(line[pos:])
    except:
        return None

    n = (ip_packet[0] << 24) | (ip_packet[1] << 16) | (ip_packet[2] << 8) | ip_packet[3]

    return (n, mask,)


def parse_ip_subnet_file(fpath):
    """解析IP地址列表文件"""
    lines = __read_from_file(fpath)
    results = []
    for line in lines:
        ret = __get_ip_subnet(line)
        if not ret: print("the wrong format on: %s" % line)
        results.append(ret)

    return results

