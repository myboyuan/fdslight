#!/usr/bin/env python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"hello,world", ("127.0.0.1", 10001))
s.close()
