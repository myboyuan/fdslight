#!/usr/bin/env python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("iplc.gg.uovz.com", 12347))
s.send(b"hello")
s.close()
