#!/usr/bin/env python3
import pywind.web.lib.httputils as httputils

sts = b'GET / HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Language: zh-CN\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063\r\nAccept-Encoding: gzip, deflate\r\nIf-Modified-Since: Sat, 15 Jul 2017 14:59:18 GMT\r\nHost: www.youku.com\r\n\r\n'

import socket

s = socket.socket()

s.connect(("www.youku.com", 80))

s.send(sts)

while 1:
    print(s.recv(4096))
