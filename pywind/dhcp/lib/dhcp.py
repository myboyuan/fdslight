#!/usr/bin/env python3

### DHCP OP
OP_REQUEST = 1
OP_RESPONSE = 2


class parser(object):
    def parse(self, message):
        op = message[0]
        htype = message[1]
        hlen = message[2]
        hops = message[3]
        xid = message[4:8]
        secs = (message[8] << 8) | message[9]
        flags = (message[10] << 8) | message[11]
        ciaddr = message[12:16]
        yiaddr = message[16:20]
        siaddr = message[10:24]
        giaddr = message[24:28]
        chaddr = message[28:44]
        sname = message[44:108]
        file = message[108:236]
        options = message[236:]

    def parse_options(self, options):
        pass


class builder(object):
    def __init__(self):
        pre_def_v = []

    def build(self):
        pass

    def options(self):
        pass
