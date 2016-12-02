#!/usr/bin/env python3
import pywind.evtframework.handler.udp_handler as udp_handler
import pywind.lib.timer as timer
import random, socket, sys
import dns.message
import fdslight_etc.fn_gw as fn_config
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils


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

    def get_dns_id(self, old_dns_id):
        if old_dns_id not in self.__dns_id_map: return old_dns_id
        while 1:
            n_dns_id = random.randint(1, 65534)
            if n_dns_id in self.__dns_id_map: continue
            break
        return n_dns_id

    def set_dns_id_map(self, dns_id, value):
        self.__dns_id_map[dns_id] = value

    def del_dns_id_map(self, dns_id):
        if dns_id in self.__dns_id_map: del self.__dns_id_map[dns_id]

    def get_dns_id_map(self, dns_id):
        return self.__dns_id_map[dns_id]

    def dns_id_map_exists(self, dns_id):
        return dns_id in self.__dns_id_map

    def recyle_resource(self, dns_ids):
        for dns_id in dns_ids:
            if dns_id not in self.__dns_id_map: continue
            del self.__dns_id_map[dns_id]
        return

    def print_dns_id_map(self):
        print(self.__dns_id_map)


class dnsd_proxy(dns_base):
    """服务端的DNS代理"""
    __TIMEOUT = 5
    __creator_fd = -1
    __timer = None

    def init_func(self, creator_fd, dns_server):
        self.__timer = timer.timer()
        self.__creator_fd = creator_fd

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        self.connect((dns_server, 53))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__TIMEOUT)
        return self.fileno

    def udp_readable(self, message, address):
        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return
        n_dns_id, session_id = self.get_dns_id_map(dns_id)
        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff,
        )

        if not self.dispatcher.is_bind_session(session_id): return
        fileno, _ = self.dispatcher.get_bind_session(session_id)
        self.ctl_handler(self.fileno, fileno, "response_dns", session_id, bytes(L))
        self.del_dns_id_map(dns_id)

        if self.__timer.exists(dns_id): self.__timer.drop(dns_id)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        dns_ids = self.__timer.get_timeout_names()
        for dns_id in dns_ids:
            if self.__timer.exists(dns_id): self.__timer.drop(dns_id)

        self.recyle_resource(dns_ids)
        self.set_timeout(self.fileno, self.__TIMEOUT)

    def handler_ctl(self, from_fd, cmd, session_id, message):
        if cmd != "request_dns": return False
        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id(dns_id)
        self.set_dns_id_map(n_dns_id, (dns_id, session_id,))

        L = list(message)
        L[0:2] = (
            (n_dns_id & 0xff00) >> 8,
            n_dns_id & 0x00ff,
        )

        self.__timer.set_timeout(n_dns_id, self.__TIMEOUT)
        self.add_evt_write(self.fileno)
        self.send(bytes(L))

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()
        sys.exit(-1)


class dnsgw_proxy(dns_base):
    """客户端的DNS代理"""
    __host_match = None
    __timer = None

    __DNS_QUERY_TIMEOUT = 5
    __TIMEOUT = 10

    __debug = False

    __transparent_dns = None

    __dev_fd = -1
    # dns flags集合
    __dns_flags = None

    __session_id = None

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

    def __send_to_dns_server(self, server, message):
        self.add_evt_write(self.fileno)
        self.sendto(message, (server, 53))

    def __send_to_client(self, message):
        dns_id = (message[0] << 8) | message[1]
        if not self.dns_id_map_exists(dns_id): return
        n_dns_id, dst_addr = self.get_dns_id_map(dns_id)
        L = list(message)
        L[0:2] = ((n_dns_id & 0xff00) >> 8, n_dns_id & 0x00ff,)

        new_pkt = bytes(L)

        self.add_evt_write(self.fileno)
        self.sendto(new_pkt, dst_addr)
        self.del_dns_id_map(dns_id)
        if self.__timer.exists(dns_id): self.__timer.drop(dns_id)
        if dns_id in self.__dns_flags: del self.__dns_flags[dns_id]

    def init_func(self, creator_fd, session_id, host_rules, debug=False):
        self.__transparent_dns = fn_config.configs["dns"]
        self.__session_id = session_id

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.__debug = debug

        self.bind((fn_config.configs["dns_bind"], 53))
        self.set_timeout(self.fileno, self.__TIMEOUT)

        self.__host_match = _host_match()
        self.__timer = timer.timer()
        self.__dns_flags = {}

        for rule in host_rules: self.__host_match.add_rule(rule)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def update_blacklist(self, host_rules):
        """更新黑名单"""
        self.__host_match.clear()
        for rule in host_rules: self.__host_match.add_rule(rule)

    def udp_readable(self, message, address):
        # dns至少有12个字节
        if len(message) < 12: return

        ipaddr, port = address

        # 把从DNS服务器收到的信息发送到客户端
        if ipaddr == self.__transparent_dns:
            self.__send_to_client(message)
            return

        dns_id = (message[0] << 8) | message[1]
        n_dns_id = self.get_dns_id(dns_id)

        self.set_dns_id_map(n_dns_id, (dns_id, address,))
        L = list(message)
        L[0:2] = ((n_dns_id & 0xff00) >> 8, n_dns_id & 0x00ff,)

        # 设置资源超时,防止占用过多内存
        self.__timer.set_timeout(n_dns_id, self.__TIMEOUT)

        message = bytes(L)

        msg = dns.message.from_wire(message)

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
        if not is_match:
            self.__send_to_dns_server(self.__transparent_dns, message)
            return

        # 没有打开隧道,尝试打开隧道
        if not self.dispatcher.is_bind_session(self.__session_id): self.dispatcher.open_tunnel()
        # 打开隧道失败,直接丢弃数据包
        if not self.dispatcher.is_bind_session(self.__session_id): return

        fileno, _ = self.dispatcher.get_bind_session(self.__session_id)

        self.__dns_flags[n_dns_id] = flags
        self.ctl_handler(self.fileno, fileno, "request_dns", message)

    def message_from_handler(self, from_fd, byte_data):
        dns_id = (byte_data[0] << 8) | byte_data[1]
        if dns_id not in self.__dns_flags: return
        msg = dns.message.from_wire(byte_data)
        for rrset in msg.answer:
            for cname in rrset:
                ip = cname.__str__()
                if not self.__check_ipaddr(ip): continue
                fdsl_ctl.tf_record_add(self.__dev_fd, utils.ip4s_2_number(ip))
                ''''''
        self.__send_to_client(byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()

    def udp_timeout(self):
        # 清除超时的DNS ID占用的资源,节约内存
        dns_ids = self.__timer.get_timeout_names()
        for dns_id in dns_ids:
            if self.__timer.exists(dns_id): self.__timer.drop(dns_id)
            if dns_id in self.__dns_flags: del self.__dns_flags[dns_id]
        self.recyle_resource(dns_ids)
        self.set_timeout(self.fileno, self.__TIMEOUT)

        return

    def udp_error(self):
        self.delete_handler(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args):
        if cmd != "set_filter_fileno": return
        self.__dev_fd, = args
        return


class dnslocal_proxy(udp_handler.udp_handler):
    __LOOP_TIMEOUT = 10
    # DNS查询超时时间
    __DNS_QUERY_TIMEOUT = 6
    __timer = None

    __dns_map = None
    __tun_fd = -1

    __session_id = None
    __match = None

    def init_func(self, creator, session_id, tun_fd, dns_server):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.set_socket(s)
        try:
            self.connect((dns_server, 53))
        except socket.gaierror:
            self.close()
            return -1

        self.__timer = timer.timer()
        self.__dns_map = {}
        self.__tun_fd = tun_fd
        self.__match = _host_match()

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__session_id = session_id
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        return self.fileno

    def udp_readable(self, message, address):
        self.__handle_dnsmsg_for_response(message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            del self.__dns_map[name]
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def message_from_handler(self, from_fd, byte_data):
        self.__handle_dnsmsg_from_tun(byte_data)

    def update_blacklist(self, rules):
        """更新黑名列表"""
        self.__match.clear()
        for rule in rules: self.__match.add_rule(rule)

    def __parse_udp(self, ip_packet):
        ihl = (ip_packet[0] & 0x0f) * 4
        a, b = (ihl, ihl + 1,)
        sport = (ip_packet[a] << 8) | ip_packet[b]

        n = ihl + 8
        message = ip_packet[n:]

        return (ip_packet[12:16], ip_packet[16:20], sport, message,)

    def __send_dns_request_transparent(self, dns_msg):
        self.add_evt_write(self.fileno)
        self.send(dns_msg)

    def __handle_dnsmsg_from_tun(self, byte_data):
        saddr, daddr, sport, dns_msg = self.__parse_udp(byte_data)
        msg = dns.message.from_wire(dns_msg)
        questions = msg.question
        dns_id = (dns_msg[0] << 8) | dns_msg[1]

        self.__dns_map[dns_id] = [saddr, daddr, sport, False]
        self.__timer.set_timeout(dns_id, self.__DNS_QUERY_TIMEOUT)

        if len(questions) != 1 or msg.opcode() != 0:
            self.__send_dns_request_transparent(dns_msg)
            return

        q = questions[0]
        host = b".".join(q.name[0:-1]).decode("iso-8859-1")
        is_match, flags = self.__host_match.match(host)

        if not is_match:
            self.__send_dns_request_transparent(dns_msg)
            return

        self.__dns_map[dns_id][3] = True
        if not self.dispatcher.is_bind_session(self.__session_id):
            self.dispatcher.open_tunnel()
        fileno, _ = self.dispatcher.get_bind_session(self.__session_id)
        self.ctl_handler(self.fileno, fileno, "request_dns", dns_msg)

    def __handle_dnsmsg_for_response(self, message):
        dns_id = (message[0] << 8) | message[1]
        if dns_id not in self.__dns_map: return

        caddr, cport, dns_server_addr, is_from_tunnel = self.__dns_map[dns_id]
        # 伪造DNS数据包
        pkts = utils.build_udp_packets(dns_server_addr, caddr, 53, cport, message)
        if is_from_tunnel:
            msg = dns.message.from_wire(message)
            for rrset in msg.answer:
                for cname in rrset:
                    ip = cname.__str__()
                    if self.dispatcher.is_set_router(ip, 32): continue
                    self.dispatcher.set_router(ip, 32)
                ''''''
            ''''''
        for pkt in pkts: self.send_message_to_handler(self.fileno, self.__tun_fd, pkt)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "response_dns": return
        dns_msg, = args
        self.__handle_dnsmsg_for_response(dns_msg)
