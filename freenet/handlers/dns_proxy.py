#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, sys
import dns.message
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils


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

        if not tmplist: return

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

    def clear(self):
        self.__rules = {}


class dns_base(udp_handler.udp_handler):
    """DNS基本类"""
    # 新的DNS ID映射到就的DNS ID
    __dns_id_map = {}

    # 空闲的dns ids
    __empty_dns_ids = []
    # 当前最大的DNS ID
    __current_max_dns_id = 0
    # 最大的DNS ID
    __max_dns_id = 2000

    def set_dns_id_max(self, max_id):
        if max_id > 65535: max_id = 65535
        if max_id < 0: max_id = self.__max_dns_id
        self.__max_dns_id = max_id

    def get_dns_id(self, old_dns_id):
        if old_dns_id not in self.__dns_id_map: return old_dns_id

        if not self.__empty_dns_ids:
            n_dns_id = self.__empty_dns_ids.pop(0)
        else:
            self.__current_max_dns_id += 1
            n_dns_id = self.__current_max_dns_id
        return n_dns_id

    def set_dns_id_map(self, dns_id, value):
        self.__dns_id_map[dns_id] = value

    def del_dns_id_map(self, dns_id):
        if dns_id in self.__dns_id_map:
            self.__empty_dns_ids.append(dns_id)
            del self.__dns_id_map[dns_id]
        return

    def get_dns_id_map(self, dns_id):
        return self.__dns_id_map[dns_id]

    def dns_id_map_exists(self, dns_id):
        return dns_id in self.__dns_id_map

    def recyle_resource(self, dns_ids):
        for dns_id in dns_ids: self.del_dns_id_map(dns_id)

    def print_dns_id_map(self):
        print(self.__dns_id_map)


class dnsd_proxy(dns_base):
    """服务端的DNS代理"""
    __LOOP_TIMEOUT = 5
    # DNS查询超时
    __QUERY_TIMEOUT = 3
    __timer = None

    def init_func(self, creator_fd, dns_server, is_ipv6=False):
        self.__timer = timer.timer()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.connect((dns_server, 53))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        return self.fileno

    def udp_readable(self, message, address):
        size = len(message)
        if size < 16: return

        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return
        n_dns_id, session_id = self.get_dns_id_map(dns_id)
        L = list(message)

        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff
        )
        self.del_dns_id_map(dns_id)
        self.__timer.drop(dns_id)

        self.dispatcher.response_dns(session_id, bytes(L))

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        dns_ids = self.__timer.get_timeout_names()
        for dns_id in dns_ids:
            if not self.__timer.exists(dns_id): continue
            self.del_dns_id_map(dns_id)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        return

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def request_dns(self, session_id, message):
        if len(message) < 16: return
        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id(dns_id)

        self.set_dns_id_map(n_dns_id, (dns_id, session_id))
        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff
        )
        self.__timer.set_timeout(n_dns_id, self.__QUERY_TIMEOUT)

        self.send(bytes(L))
        self.add_evt_write(self.fileno)


class udp_client_for_dns(udp_handler.udp_handler):
    __creator = None

    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__creator = creator
        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.connect((address, 53))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        self.send_message_to_handler(self.fileno, self.__creator, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, message):
        self.add_evt_write(self.fileno)
        self.send(message)


class dnsc_proxy(dns_base):
    """客户端的DNS代理
    """
    __host_match = None
    __timer = None

    __DNS_QUERY_TIMEOUT = 5
    __LOOP_TIMEOUT = 10

    __debug = False
    __dnsserver = None
    __server_side = False

    __udp_client = None
    __is_ipv6 = False

    def init_func(self, creator, address, debug=False, is_ipv6=False, server_side=False):
        self.__is_ipv6 = is_ipv6

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.__server_side = server_side

        if server_side:
            self.bind((address, 53))
        else:
            self.connect((address, 53))

        self.__debug = debug
        self.__host_match = _host_match()
        self.__timer = timer.timer()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def set_parent_dnsserver(self, server, is_ipv6=False):
        """当作为网关模式时需要调用此函数来设置上游DNS
        :param server:
        :return:
        """
        self.__udp_client = self.create_handler(self.fileno, udp_client_for_dns, server, is_ipv6=is_ipv6)

    def __handle_msg_from_response(self, message):
        try:
            msg = dns.message.from_wire(message)
        except:
            return

        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return

        saddr, daddr, dport, n_dns_id, flags = self.get_dns_id_map(dns_id)
        self.del_dns_id_map(dns_id)
        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff,
        )
        message = bytes(L)

        if flags == 1:
            for rrset in msg.answer:
                for cname in rrset:
                    ip = cname.__str__()
                    if utils.is_ipv4_address(ip): self.dispatcher.set_router(ip, is_dynamic=True)
                    if utils.is_ipv6_address(ip): self.dispatcher.set_router(ip, is_ipv6=True, is_dynamic=True)
                ''''''
            ''''''
        if not self.__server_side:
            packets = utils.build_udp_packets(saddr, daddr, 53, dport, message, is_ipv6=self.__is_ipv6)
            for packet in packets:
                self.dispatcher.send_msg_to_tun(packet)

            self.del_dns_id_map(dns_id)
            self.__timer.drop(dns_id)
            return

        if self.__is_ipv6:
            sts_daddr = socket.inet_ntop(socket.AF_INET6, daddr)
        else:
            sts_daddr = socket.inet_ntop(socket.AF_INET, daddr)

        self.del_dns_id_map(dns_id)
        self.__timer.drop(dns_id)
        self.sendto(message, (sts_daddr, dport))
        self.add_evt_write(self.fileno)

    def __handle_msg_for_request(self, saddr, daddr, sport, message):
        size = len(message)

        if size < 8: return

        try:
            msg = dns.message.from_wire(message)
        except:
            return

        questions = msg.question

        if len(questions) != 1 or msg.opcode() != 0:
            self.__send_to_dns_server(self.__transparent_dns, message)
            return

        """
        q = questions[0]
        if q.rdtype != 1 or q.rdclass != 1:
            self.__send_to_dns_server(self.__transparent_dns, message)
            return
        """

        q = questions[0]
        host = b".".join(q.name[0:-1]).decode("iso-8859-1")
        pos = host.find(".")

        if pos > 0 and self.__debug: print(host)
        is_match, flags = self.__host_match.match(host)

        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id(dns_id)

        if not is_match: flags = None

        self.set_dns_id_map(n_dns_id, (daddr, saddr, sport, dns_id, flags))

        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0xff,
        )

        message = bytes(L)
        self.__timer.set_timeout(n_dns_id, self.__DNS_QUERY_TIMEOUT)

        if not is_match and self.__server_side:
            self.send_message_to_handler(self.fileno, self.__udp_client, message)
            return

        if not is_match and not self.__server_side:
            self.send(message)
            self.add_evt_write(self.fileno)
            return
        self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_DNS, message)

    def message_from_handler(self, from_fd, message):
        self.__handle_msg_from_response(message)

    def msg_from_tunnel(self, message):
        self.__handle_msg_from_response(message)

    def set_host_rules(self, rules):
        self.__host_match.clear()
        for rule in rules: self.__host_match.add_rule(rule)

    def dnsmsg_from_tun(self, saddr, daddr, sport, message):
        self.__handle_msg_for_request(saddr, daddr, sport, message)

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.del_dns_id_map(name)
            self.__timer.drop(name)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_readable(self, message, address):
        if self.__server_side:
            if self.__is_ipv6:
                byte_saddr = socket.inet_pton(socket.AF_INET6, address[0])
            else:
                byte_saddr = socket.inet_pton(socket.AF_INET, address[0])
            self.__handle_msg_for_request(byte_saddr, None, address[1], message)
            return
        self.__handle_msg_from_response(message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
