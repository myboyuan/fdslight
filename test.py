#!/usr/bin/env python3
import socket, time
import socket

s = socket.socket()

s.connect(("127.0.0.1", 8080))
s.send(b"hello,websocket")
s.recv(2048)
s.close()
