#!/usr/bin/env python3
import pywind.lib.timer as timer
import struct, socket

_IP4HDR = "!BBHHHBBH4s4s"


class ip4frag_merge(object):
    """IPV4分包合并
    """
    __timer = None
    __ok_packets = None
    __fragdata = None

    def __init__(self):
        self.__timer = timer.timer()
        self.__ok_packets = []
        self.__fragdata = {}

    def add_frag(self, message):
        v, tos, tot_len, _id, frag_off, ttl, proto, csum, saddr, daddr = struct.unpack(_IP4HDR, message[0:20])
        hdr_len = (v & 0x0f) * 4
        entity = message[hdr_len:]

        # df = (frag_off & 0x4000) >> 14
        mf = (frag_off & 0x2000) >> 13
        offset = frag_off & 0x1fff

        name = self.__get_fragid(saddr, _id)
        print(mf)

        if offset == 1:
            sport, dport = self.__get_udp_port(entity)
            print(sport,dport)
            entity = entity[8:]
            if dport == 0: return

            self.__fragdata[name] = (saddr, daddr, proto, sport, dport, [])
            self.__timer.set_timeout(name, 30)

        if name not in self.__fragdata: return

        rs = self.__fragdata[name]
        rs[5].append(entity)

        if mf == 0:
            saddr, daddr, proto, sport, dport, seq = rs
            sts_saddr = socket.inet_ntop(socket.AF_INET, saddr)
            sts_daddr = socket.inet_ntop(socket.AF_INET, daddr)
            self.__ok_packets.append((sts_saddr, sts_daddr, proto, sport, dport, b"".join(seq),))
            self.__timer.drop(name)
        return

    def get_data(self):
        self.__recycle()
        try:
            return self.__ok_packets.pop(0)
        except IndexError:
            return None

    def __recycle(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            del self.__fragdata[name]

    def __get_fragid(self, saddr, _id):
        return "%s-%s" % (saddr, _id)

    def __get_udp_port(self, entity):
        sport, dport = struct.unpack("!HH", entity[0:4])
        return (sport, dport,)
