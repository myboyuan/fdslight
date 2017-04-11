#!/usr/bin/env python3

sts = """for n in range(100):
    if n > 10: n = n + 10, print(n)"""


def hello():

    exec(sts)

hello()
