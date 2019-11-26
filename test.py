#!/usr/bin/env python3

import dns.resolver

res = dns.resolver.Resolver()
res.nameservers=["127.0.0.1"]
r = res.query("www.google.com", "a")

for record in r:
    print(record)
