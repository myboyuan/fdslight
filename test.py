#!/usr/bin/env python3

import socket


def gen_magic_packet(hwaddr):
    a = [255, 255, 255, 255, 255, 255]
    byte_a = bytes(a)

    a = []
    seq = hwaddr.split(":")
    for s in seq:
        v = int("0x%s" % s, 16)
        a.append(v)
    b = bytes(a)
    b = b * 16

    return b"".join([byte_a, b])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

pkt = gen_magic_packet("98:F2:B3:F0:4A:18")

s.sendto(pkt, ("255.255.255.255", 7))
