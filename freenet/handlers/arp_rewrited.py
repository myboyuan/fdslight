#!/usr/bin/env python3

import pywind.evtframework.handlers.handler as handler
import socket, struct, time

import freenet.lib.netif_hwinfo as hwinfo


class arp_rewrite(handler.handler):
    __s = None
    __sent = None

    # 存放临时记录,便于ARP重写
    __arp_cache = None
    __if_hwaddr = None

    def init_func(self, creator_fd, if_name):
        self.__sent = []
        self.__arp_cache = {}
        self.__if_hwaddr = hwinfo.hwaddr_get(if_name)

        if not self.__if_hwaddr:
            raise ValueError("wrong network card name,maybe it is not exists")

        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x806))
        s.setblocking(0)
        s.bind((if_name, 0,))

        self.__s = s
        self.set_fileno(s.fileno())
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def evt_read(self):
        count = 10
        while count >= 0:
            try:
                pkt = self.__s.recv(4096)
            except BlockingIOError:
                break
            self.handle_arppkt(pkt)
            count -= 1

    def evt_write(self):
        while 1:
            try:
                pkt = self.__sent.pop(0)
                self.__s.send(pkt)
            except IndexError:
                self.remove_evt_write(self.fileno)
                break
            except BlockingIOError:
                self.__sent.insert(0, pkt)
                break
            ''''''
        return

    def handle_arppkt(self, message):
        if len(message) < 42: return

        message = message[0:42]
        dst_hwaddr, src_hwaddr, _type, data = struct.unpack("!6s6sH28s", message)
        hw_type, proto_type, hw_len, proto_len, op, sender_hwaddr, sender_ipaddr, receiver_hwaddr, receiver_ipaddr = struct.unpack(
            "!HHBBH6s4s6s4s", data
        )
        if src_hwaddr != sender_hwaddr: return

        # 只支持ARP请求与响应
        if op not in (1, 2,): return

        # 处理ARP请求
        if (1 == op):
            # 发送ARP响应
            arppkt = struct.pack("!HHBBH6s4s6s4s", hw_type, proto_type, hw_len, proto_len, self.__if_hwaddr,
                                 receiver_ipaddr,
                                 sender_hwaddr, sender_ipaddr)
            link_data = struct.pack("!6s6sH28s", sender_hwaddr, self.__if_hwaddr, _type, arppkt)
            self.__sent.append(link_data)
            self.add_evt_write(self.fileno)
            return
        # 对ARP响应进行重写,并发送给客户端

    def arp_msg_send(self, message):
        """修改ARP请求报文
        :param message:
        :return:
        """
        if message < 42: return
        seq = list(message)
        message = message[0:42]
        src_hwaddr = message[6:12]
        src_sender_hwaddr = message[22:28]
        src_ipaddr = message[28:32]

        # 检查ARP包是否合法
        if src_hwaddr != src_sender_hwaddr: return

        # 加入到映射记录
        self.__arp_cache = {src_ipaddr: (src_hwaddr, time.time(),)}

        seq[6:12] = list(self.__if_hwaddr)
        seq[22:28] = list(self.__if_hwaddr)

        new_msg = bytes(seq)
        self.__sent.append(new_msg)
        self.add_evt_write(self.fileno)

    def timeout(self):
        dels = []
        t = time.time()

        for ipaddr in self.__arp_cache:
            hwaddr, old_t = self.__arp_cache[ipaddr]
            if t - old_t >= 10: dels.append(ipaddr)

        for ipaddr in dels: del self.__arp_cache[ipaddr]
        self.set_timeout(self.fileno, 10)

    def delete(self):
        self.unregister(self.fileno)
        self.__s.close()
