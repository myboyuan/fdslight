#!/usr/bin/env python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("119.147.144.130", 12347))
s.send(b"hello")
s.close()
