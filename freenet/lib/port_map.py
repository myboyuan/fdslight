#!/usr/bin/env python3
"""端口映射相关处理
"""
import socket, struct


class port_map(object):
    __is_ipv6 = None

    __rules = None

    def __init__(self, is_ipv6=False):
        self.__rules = {}
        self.__is_ipv6 = is_ipv6

    def __get_protcol_number(self, name):
        m = {
            "tcp": 6,
            "udp": 17,
            "sctp": 132,
            "udplite": 136.
        }

        return m.get(name, -1)

    def add_rule(self, ip: str, protocol: str, port: int, extra_data=None):
        """
        :param ip:重写之后的IP地质
        :param protocol:
        :param port:
        :return:
        """
        p = self.__get_protcol_number(protocol)
        if p < 0:
            raise ValueError("wrong protocol value %s,it must be tcp,udp,sctp or udplite" % protocol)

        if self.__is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        byte_ip = socket.inet_pton(fa, ip)
        k = struct.pack("BH", p, port)
        self.__rules[k] = (byte_ip, extra_data,)

    def find_rule(self, protocol_number: int, port: int):
        k = struct.pack("BH", protocol_number, port)
        return self.__rules.get(k, None)

    def del_rule(self, protocol: str, port: int):
        p = self.__get_protcol_number(protocol)
        if p < 0:
            raise ValueError("wrong protocol value %s,it must be tcp,udp,sctp or udplite" % protocol)

        k = struct.pack("BH", p, port)

        del self.__rules[k]
