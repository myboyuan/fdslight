#!/usr/bin/env python3


import freenet.lib.utils as utils

class ip_match(object):
    __ip_rules = None
    __ipv6_rules = None

    def __init__(self):
        self.__ip_rules = []
        self.__ipv6_rules = []

    def add_rule(self, subnet, prefix):
        prefix = int(prefix)
        if prefix < 1: return False

        if utils.is_ipv4_address(subnet) and prefix > 32: return False
        if utils.is_ipv6_address(subnet) and prefix > 128: return False
        if not utils.is_ipv6_address(subnet) and not utils.is_ipv4_address(subnet): return False

        is_ipv6 = False
        if utils.is_ipv6_address(subnet): is_ipv6 = True
        if not utils.check_subnet_fmt(subnet, prefix, is_ipv6=is_ipv6): return False

        if is_ipv6:
            self.__ipv6_rules.append((subnet, prefix,))
        else:
            self.__ip_rules.append((subnet, prefix,))

        return True

    def match(self, ipaddr, is_ipv6=False):
        if is_ipv6:
            rules = self.__ipv6_rules
        else:
            rules = self.__ip_rules
        result = False
        for subnet, prefix in rules:
            rs = utils.check_is_from_subnet(ipaddr, subnet, prefix, is_ipv6=is_ipv6)
            if not rs: continue
            result = True
            break

        return result

    def clear(self):
        self.__ip_rules = []
        self.__ipv6_rules = []
