#!/usr/bin/env python3
import socket, time

s = socket.socket()

s.connect(("127.0.0.1", 8080))

time.sleep(5)
