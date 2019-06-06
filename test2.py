#!/usr/bin/env python3

import socket, ssl,select

s = socket.socket()
s.connect(("www.wss.ws",443))
s.setblocking(0)

s=ssl.wrap_socket(s,do_handshake_on_connect=False)

while True:
    try:
        rs=s.do_handshake()
        print(rs)
        break
    except ssl.SSLWantReadError:
        select.select([s], [], [])
    except ssl.SSLWantWriteError:
        select.select([], [s], [])