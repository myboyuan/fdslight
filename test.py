#!/usr/bin/env python3
import random


def times33(byte_data):
    hv = 5381
    for n in byte_data:
        hv += (hv << 5) + n

    return hv & 0x7fffffff


def rand_sts(size):
    sts = b"1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    rv = []

    for i in range(size):
        n = random.randint(0, 61)
        rv.append(sts[n])

    return bytes(rv)


conflic = {}

for n in range(1000):
    byte_data = rand_sts(4)
    hv = times33(byte_data) % 1000

    if hv not in conflic:
        conflic[hv] = 1
    else:
        conflic[hv] += 1

print(conflic)
