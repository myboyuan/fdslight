#!/usr/bin/env python3
import pywind.lib.timer as timer
import struct

_IP4HDR = "!BBHHHBBHII"


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
        v, tos, tot_len, _id, offset, ttl, proto, csum, saddr, daddr = struct.unpack(_IP4HDR, message)




    def get_packet(self):
        try:
            return self.__ok_packets.pop(0)
        except IndexError:
            return None

    def recycle(self):
        pass

    def __get_fragid(self, message):
        pass
