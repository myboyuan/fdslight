#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.lib.timer as timer
import socket, sys, struct

import freenet.lib.utils as utils
import freenet.lib.logging as logging
import freenet.lib.socks2https as socks2https

try:
    import dns.message
except ImportError:
    print("please install dnspython3 module")
    sys.exit(-1)


class dns_client(udp_handler.udp_handler):
    __creator = None

    def init_func(self, creator_fd, dnsserver, is_ipv6=False):
        self.__creator = creator_fd
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        self.set_socket(s)
        self.connect((dnsserver, 53))
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        self.send_message_to_handler(self.fileno, self.__creator, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        pass

    def udp_error(self):
        self.dispatcher.tell_dns_client_close()

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, data):
        self.send(data)
        self.add_evt_write(self.fileno)


class dns_proxy(udp_handler.udp_handler):
    __query_timer = None
    __dns_map = None
    __dnsserver = None
    __proxy_dnsserver = None
    __empty_ids = None
    __cur_max_dns_id = 1
    __packet_id = None
    __is_ipv6 = None
    __is_sent_handshake = None
    __conn_ok = None
    __dns_client = None

    def init_func(self, creator_fd, address, dnsserver, proxy_dnsserver, is_ipv6=False):
        self.__query_timer = timer.timer()
        self.__dnsserver = dnsserver
        self.__proxy_dnsserver = proxy_dnsserver
        self.__dns_client = -1
        self.__cur_max_dns_id = 1
        self.__empty_ids = []
        self.__packet_id = -1
        self.__is_ipv6 = is_ipv6
        self.__is_sent_handshake = False
        self.__conn_ok = False
        self.__dns_map = {}

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)

        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def get_dns_id(self):
        n_dns_id = -1
        try:
            n_dns_id = self.__empty_ids.pop(0)
            return n_dns_id
        except IndexError:
            pass

        if self.__cur_max_dns_id < 65536:
            n_dns_id = self.__cur_max_dns_id
            self.__cur_max_dns_id += 1

        return n_dns_id

    def send_query_request(self, dns_msg, address):
        """发送查询请求
        :return:
        """
        if len(dns_msg) < 8: return
        if self.__dns_client < 0:
            self.__dns_client = self.create_handler(self.fileno, dns_client, self.__dnsserver, is_ipv6=self.__is_ipv6)

        # 检查查询以及匹配查询请求
        dns_id = (dns_msg[0] << 8) | dns_msg[1]

        new_dns_id = self.get_dns_id()
        if new_dns_id < 1:
            logging.print_error("not enough dns id,dns server is busy")
            return

        dns_msg = b"".join([
            struct.pack("!H", new_dns_id),
            dns_msg[2:]
        ])

        try:
            msg = dns.message.from_wire(dns_msg)
        except:
            # 发生异常那么回收DNS ID
            self.__empty_ids.append(new_dns_id)
            return

        self.__query_timer.set_timeout(new_dns_id, 10)
        self.__dns_map[new_dns_id] = [dns_id, address, -1]

        questions = msg.question
        if len(questions) != 1 or msg.opcode() != 0:
            self.sendto(dns_msg, (self.__dnsserver, 53,))
            self.add_evt_write(self.fileno)
            return

        q = questions[0]
        host = b".".join(q.name[0:-1]).decode("iso-8859-1")
        pos = host.find(".")

        if self.dispatcher.debug: print(host)

        if pos > 0 and self.dispatcher.debug: print(host)
        is_match, flags = self.dispatcher.match_domain(host)

        # 丢弃DNS请求
        if is_match and flags == 2:
            self.__query_timer.drop(new_dns_id)
            self.__empty_ids.append(new_dns_id)
            del self.__dns_map[new_dns_id]
            return

        if not is_match:
            self.send_message_to_handler(self.fileno, self.__dns_client, dns_msg)
            return

        self.__dns_map[new_dns_id][2] = flags
        self.send_conn_frame(dns_msg)

    def handle_from_dnsserver(self, dns_msg):
        if len(dns_msg) < 6: return
        dns_id = (dns_msg[0] << 8) | dns_msg[1]
        # 检查是否在映射当中
        if dns_id not in self.__dns_map: return

        my_dns_id, address, flags = self.__dns_map[dns_id]
        self.__empty_ids.append(dns_id)

        if self.__query_timer.exists(dns_id):
            self.__query_timer.drop(dns_id)
            del self.__dns_map[dns_id]

        dns_msg = b"".join([
            struct.pack("!H", my_dns_id),
            dns_msg[2:]
        ])

        try:
            msg = dns.message.from_wire(dns_msg)
        except:
            return
        for rrset in msg.answer:
            for cname in rrset:
                ip = cname.__str__()
                if utils.is_ipv4_address(ip) or utils.is_ipv6_address(ip):
                    if 1 == flags: self.dispatcher.match_host_rule_add(ip)
                ''''''
            ''''''
        self.sendto(dns_msg, address)
        self.add_evt_write(self.fileno)

    def send_conn_frame(self, byte_data):
        if self.__is_ipv6:
            addr_type = socks2https.ADDR_TYPE_IPv6
        else:
            addr_type = socks2https.ADDR_TYPE_IP
        if not byte_data:
            _t = socks2https.FRAME_TYPE_UDP_CONN
        else:
            _t = socks2https.FRAME_TYPE_UDP_DATA
        self.dispatcher.send_conn_frame(
            _t, self.__packet_id, self.__proxy_dnsserver, 53, addr_type, data=byte_data
        )

    def udp_readable(self, message, address):
        if not self.__is_sent_handshake:
            self.__is_sent_handshake = True
            self.send_conn_frame(b"")

        if address[0] == self.__dnsserver:
            if address[1] != 53: return
            self.handle_from_dnsserver(message)
            return

        if self.__packet_id < 1:
            self.__packet_id = self.dispatcher.alloc_packet_id(self.fileno)

        self.send_query_request(message, address)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        names = self.__query_timer.get_timeout_names()
        for name in names:
            if self.__query_timer.exists(name):
                self.__query_timer.drop(name)
            if name in self.__dns_map:
                self.__empty_ids.append(name)
                del self.__dns_map[name]
            ''''''
        self.set_timeout(self.fileno, 10)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        if self.__packet_id > 0:
            self.dispatcher.free_packet_id(self.__packet_id)
        self.unregister(self.fileno)
        self.close()

    def handle_udp_udplite_data(self, address, message):
        if address[0] != self.__proxy_dnsserver: return
        if address[1] != 53: return

        self.handle_from_dnsserver(message)

    def tell_close(self):
        if self.dispatcher.debug:
            print("remote server error at DNS")
        self.__conn_ok = False
        self.__is_sent_handshake = False

    def tell_conn_ok(self):
        self.__conn_ok = True

    def message_from_handler(self, from_fd, data):
        self.handle_from_dnsserver(data)

    def tell_dns_client_close(self):
        self.delete_handler(self.__dns_client)
        self.__dns_client = -1
