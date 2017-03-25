#!/usr/bin/env python3
import socket

import dns.resolver

r = dns.resolver.Resolver()
r.nameservers=["192.168.231.140"]
an=r.query("www.google.com")

for rs in an:
    print(rs)
