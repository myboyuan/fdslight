#!/usr/bin/env python3
import sys

import scapy.all

sys.path.append("../../")

import freenet.lib.utils as utils

saddr = "192.168.1.10"
daddr = "192.168.1.2"
sport = 9900
dport = 8800

msg = b"hello"

pkt = scapy.all.IP(src=saddr, dst=daddr) / scapy.all.UDP(dport=dport, sport=sport) / msg

a = pkt.__bytes__()
b = utils.build_udp_packet(saddr, daddr, sport, dport,msg)

print(a)
print(b)
