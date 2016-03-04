#!/usr/bin/env python3
import dns.resolver

r=dns.resolver.Resolver()
r.nameservers=["127.0.0.1",]

qs=r.query("www.facebook.com")

for rs in qs:
    print(rs)

