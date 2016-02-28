#!/usr/bin/env python3
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.sendto(b"hello,world",("192.168.1.10",8800))

print(s.recvfrom(4096))