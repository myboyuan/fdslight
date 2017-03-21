#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handlers.handler as handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, os, time
import freenet.lib.fdsl_ctl as fdsl_ctl
import freenet.lib.utils as utils


class _qos(object):
    __queue = None

    def __init__(self):
        self.__queue = {}

    def add_data(self, ip_data):
        saddr = ip_data[12:16]
        if saddr not in self.__queue: self.__queue[saddr] = []
        self.__queue[saddr].append(ip_data)

    def get_data(self):
        results = []
        names = []

        for saddr in self.__queue:
            t = self.__queue[saddr]
            if t: results.append(t.pop(0))
            if not t: names.append(saddr)

        for saddr in names: del self.__queue[saddr]

        return results

    def has_data(self):
        return bool(self.__queue)


class traffic_read(handler.handler):
    """读取局域网的源数据包"""
    __tunnel_fd = -1
    __qos = None

    def init_func(self, creator_fd):
        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        self.__tunnel_fd = creator_fd
        self.__qos = _qos()

        self.set_fileno(fileno)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        sent_list = self.__qos.get_data()

        if not self.handler_exists(self.__tunnel_fd): return
        for ip_data in sent_list:
            self.send_message_to_handler(self.fileno, self.__tunnel_fd, ip_data)

        self.add_to_loop_task(self.fileno)
        """最多读取20个数据包,防止陷入死循环"""
        for i in range(20):
            try:
                pkt = os.read(self.fileno, 8192)
            except BlockingIOError:
                break
            if not pkt: continue
            self.__qos.add_data(pkt)
        return

    def delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)

    def task_loop(self):
        if not self.__qos.has_data():
            self.del_loop_task(self.fileno)
            return
        self.evt_read()


class p2p_proxy(udp_handler.udp_handler):
    # 代理超时时间
    __PROXY_TIMEOUT = 180
    __LOOP_TIMEOUT = 10

    __byte_internal_ip = None
    __port = None

    # 允许发送的对端机器
    __permits = None

    __update_time = 0

    __session_id = None

    def init_func(self, creator_fd, session_id, internal_address, is_udplite=False):
        if not is_udplite:
            proto = 17
        else:
            proto = 136

        self.__update_time = time.time()
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

        udp_packets = utils.build_udp_packets(n_saddr, self.__byte_internal_ip, sport, self.__port, message)

        for udp_pkt in udp_packets:
            self.dispatcher.send_msg_to_tunnel_from_p2p_proxy(self.__session_id, udp_pkt)
        return

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
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
