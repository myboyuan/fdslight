#!/usr/bin/env python3
import socket
import ssl

HOST = 'www.google.com'
PORT = 443

ctx = ssl._create_unverified_context()
ctx.set_alpn_protocols(['h2', 'http/1.1'])

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((HOST, PORT))
conn = ctx.wrap_socket(conn
                       , server_hostname=HOST)

print('Next protocol:', conn.selected_alpn_protocol())
