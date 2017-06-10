#!/usr/bin/env python3
import ssl, socket

host = "www.freekai.net"
port = 443

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2', 'http/1.1'])
ctx.load_verify_locations(capth="pywind/certs")
s = socket.socket()

s = ctx.wrap_socket(s, server_hostname=host)
s.connect((host,port))
print(s.selected_alpn_protocol())

s.close()
