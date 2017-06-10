#!/usr/bin/env python3
import socket
import ssl

HOST = 'www.google.com'
PORT = 443

ctx = ssl._create_unverified_context()
ctx.set_alpn_protocols(['h2', 'http/1.1'])

conn = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
conn.connect((HOST, PORT))

print('Next protocol:', conn.selected_alpn_protocol())
