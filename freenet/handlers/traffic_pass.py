#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handlers.handler as handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, os, time
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.ippkts as ippkts
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils


class traffic_read(handler.handler):
    """读取局域网的源数据包"""
    __tunnel_fd = -1

    def init_func(self, creator_fd, gw_configs):
        """
        :param creator_fd:
        :param tunnel_ip: 隧道IPV4或者IPV6地址
        :param gw_configs:
        :return:
        """
        dgram_proxy_subnet, prefix = utils.extract_subnet_info(gw_configs["dgram_proxy_subnet"])
        dgram_proxy_subnet6, prefix6 = utils.extract_subnet_info(gw_configs["dgram_proxy_subnet6"])

        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        subnet = utils.calc_subnet(dgram_proxy_subnet, prefix, is_ipv6=False)
        subnet6 = utils.calc_subnet(dgram_proxy_subnet6, prefix6, is_ipv6=True)

        byte_subnet = socket.inet_aton(subnet)
        byte_subnet6 = socket.inet_pton(socket.AF_INET6, subnet6)

        r = fdsl_ctl.set_udp_proxy_subnet(fileno, byte_subnet, prefix, False)

        r = fdsl_ctl.set_udp_proxy_subnet(
            fileno, byte_subnet6,
            prefix, True
        )

        self.__tunnel_fd = creator_fd

        self.set_fileno(fileno)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def set_tunnel_ip(self, tunnel_ip):
        if utils.is_ipv6_address(tunnel_ip):
            r = fdsl_ctl.set_tunnel(self.fileno, socket.inet_pton(socket.AF_INET6, tunnel_ip), True)
        else:
            r = fdsl_ctl.set_tunnel(self.fileno, socket.inet_aton(tunnel_ip), False)

        return

    def evt_read(self):
        n = 0
        while n < 5:
            try:
                pkt = os.read(self.fileno, 8192)
                self.dispatcher.send_msg_to_tunnel(proto_utils.ACT_DATA, pkt)
            except BlockingIOError:
                break
            n += 1
            if not pkt: continue
        return

    def delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)


class p2p_proxy(udp_handler.udp_handler):
    # 代理超时时间
    __PROXY_TIMEOUT = 180
    __LOOP_TIMEOUT = 10

    __internal_ip = None
    __byte_internal_ip = None
    __port = None

    # 允许发送的对端机器
    __permits = None

    __update_time = 0

    __session_id = None
    __is_udplite = False

    def init_func(self, creator_fd, session_id, internal_address, is_udplite=False):
        if not is_udplite:
            proto = 17
        else:
            proto = 136

        self.__is_udplite = is_udplite
        self.__update_time = time.time()
        self.__internal_ip = internal_address[0]
        self.__byte_internal_ip = socket.inet_aton(internal_address[0])
        self.__port = internal_address[1]

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto)
        self.__permits = {}

        self.set_socket(s)
        self.bind(("0.0.0.0", 0))

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__session_id = session_id

        return self.fileno

    def udp_readable(self, message, address):
        addr_id = "%s-%s" % address
        if addr_id not in self.__permits: return

        self.__update_time = time.time()
        n_saddr = socket.inet_aton(address[0])
        sport = address[1]

        udp_packets = ippkts.build_udp_packets(
            n_saddr, self.__byte_internal_ip,
            sport, self.__port, message,
            is_udplite=self.__is_udplite
        )

        for udp_pkt in udp_packets:
            self.dispatcher.send_msg_to_tunnel_from_p2p_proxy(self.__session_id, udp_pkt)
        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.tell_del_udp_proxy(self.__session_id, self.__internal_ip, self.__port)
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time()

        if t - self.__update_time > self.__PROXY_TIMEOUT:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def send_msg(self, message, address):
        self.add_evt_write(self.fileno)
        self.sendto(message, address)

        addr_id = "%s-%s" % address
        if addr_id not in self.__permits: self.__permits[addr_id] = None
