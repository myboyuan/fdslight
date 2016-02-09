#!/usr/bin/env python3
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import os, socket
import fdslight_etc.fdns as dns_config
import fdslight_etc.fdns_rules as dns_rules
import freeroute.handler.dnsc_proxy as dnsc_proxy
import random
import dns.message


class _DNSProtoErr(Exception):
    pass


class _host_match(object):
    """对域名进行匹配,以找到是否在符合的规则列表中
    """
    __rules = None

    def __init__(self):
        self.__rules = {}

    def add_rule(self, host):
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
                    old_dict[old_name] = name
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

    def is_match(self, host):
        tmplist = host.split(".")
        tmplist.reverse()

        is_match = False

        tmpdict = self.__rules
        for name in tmplist:
            if name not in tmpdict:
                break

            v = tmpdict[name]

            if v == "*" or not isinstance(v, dict):
                is_match = True
                break

            tmpdict = v

        return is_match


class dnsd_proxy(udp_handler.udp_handler):
    __trans_dns_client_fd = -1
    __encrypt_dns_client_fd = -1

    __host_match = None
    # 新旧dns id映射
    __dns_id_map = None
    __timer = None
    __TIMEOUT = 6

    # 已经添加了路由的IP地址列表
    __route_ips = None
    # 需要路由的dns id
    __need_route_host = None
    __debug = False

    def __check_ipaddr(self, sts):
        """检查是否是IP地址
        :param sts:
        :return:
        """
        tmplist = sts.split(".")
        if len(tmplist) != 4:
            return False

        for i in tmplist:
            try:
                _ = int(i)
            except ValueError:
                return False
        return True

    def init_func(self, creator_fd, debug=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bind_addr = dns_config.configs["bind_addr"]

        self.__debug = debug
        s.bind((bind_addr, 53))

        self.set_socket(s)
        cmd = "route add -host %s dev fn_client" % dns_config.configs["encrypt_dns"]
        os.system(cmd)

        self.__trans_dns_client_fd = self.create_handler(self.fileno, dnsc_proxy.dnsc_proxy,
                                                         dns_config.configs["transparent_dns"])
        self.__encrypt_dns_client_fd = self.create_handler(self.fileno, dnsc_proxy.dnsc_proxy,
                                                           dns_config.configs["encrypt_dns"])
        self.__host_match = _host_match()
        self.__dns_id_map = {}
        self.__timer = timer.timer()
        self.__need_route_host = {}
        self.__route_ips = {}

        for rule in dns_rules.rules:
            self.__host_match.add_rule(rule)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        # dns至少有12个字节
        if len(message) < 12:
            return
        dns_id = (message[0] << 8) | message[1]
        n_dns_id = dns_id
        # 防止dns id出现冲突
        while 1:
            if n_dns_id in self.__dns_id_map:
                n_dns_id = random.randint(1, 65535)
                continue
            break
        L = list(message)

        L[0:2] = [
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff
        ]
        t_fd = self.__trans_dns_client_fd
        self.__dns_id_map[n_dns_id] = (dns_id, address)
        message = bytes(L)

        msg = dns.message.from_wire(message)

        # 设置资源超时,防止占用过多内存
        self.__timer.set_timeout(n_dns_id, self.__TIMEOUT)
        questions = msg.question

        if len(questions) != 1 or msg.opcode() != 0:
            self.send_message_to_handler(self.fileno, t_fd, message)
            return

        q = questions[0]
        if q.rdtype != 1 or q.rdclass != 1:
            self.send_message_to_handler(self.fileno, t_fd, message)
            return

        q = questions[0]
        host = b".".join(q.name[0:-1]).decode("utf-8")
        pos = host.find(".")

        if pos > 0 and self.__debug:
            print(host)

        if self.__host_match.is_match(host) and pos > 0:
            t_fd = self.__encrypt_dns_client_fd
            self.__need_route_host[n_dns_id] = None

        #t_fd = self.__encrypt_dns_client_fd
        self.send_message_to_handler(self.fileno, t_fd, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def message_from_handler(self, from_fd, byte_data):
        dns_id = (byte_data[0] << 8) | byte_data[1]
        if dns_id not in self.__dns_id_map:
            return
        n_dns_id, address = self.__dns_id_map[dns_id]
        L = list(byte_data)
        L[0:2] = [
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff
        ]
        message = bytes(L)
        if dns_id in self.__need_route_host:
            msg = dns.message.from_wire(message)
            for rrset in msg.answer:
                for cname in rrset:
                    ip = cname.__str__()
                    if not self.__check_ipaddr(ip):
                        continue
                    if ip in self.__route_ips:
                        continue
                    cmd = "route add -host %s dev fn_client" % ip
                    os.system(cmd)
                    self.__route_ips[ip] = None
                ''''''
            del self.__need_route_host[dns_id]

        self.add_evt_write(self.fileno)
        self.sendto(message, address)

        del self.__dns_id_map[dns_id]

    def udp_delete(self):
        pass

    def udp_timeout(self):
        # 清除超时的DNS ID占用的资源,节约内存
        dns_ids = self.__timer.get_timeout_names()
        for dns_id in dns_ids:
            if dns_id in self.__dns_id_map:
                del self.__dns_id_map[dns_id]
            continue
        return

    def udp_error(self):
        pass
