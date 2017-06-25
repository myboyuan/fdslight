#!/usr/bin/env python3

import pywind.web.lib.httpchunked as httpchunked

with open("debug.txt", "rb") as f:
    data = f.read()

p = data.find(b"\r\n\r\n")

p += 4

hc = httpchunked.parser()
hc.input(data[p:])

hc.parse()

print(hc.get_chunk())

