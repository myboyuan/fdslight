#!/usr/bin/env python3
import fn_utils
import scapy.all
import os, socket

tun_fd = fn_utils.tuntap_create("test_tun", fn_utils.IFF_TUN | fn_utils.IFF_NO_PI)
fn_utils.interface_up("test_tun")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 8800))
meesage, address = s.recvfrom(4096)
ipaddr, port = address

pkt = scapy.all.IP(src="192.168.1.10", dst=ipaddr) / scapy.all.UDP(dport=port, sport=8800) / b"hello"
print(os.write(tun_fd, pkt.__bytes__()))
