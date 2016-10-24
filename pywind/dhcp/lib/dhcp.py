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

        key_v = [
            ("op", op), ("htype", htype), ("hlen", hlen), ("hops", hops), ("xid", xid),
            ("secs", secs), ("flags", flags), ("ciaddr", ciaddr), ("yiaddr", yiaddr), ("siaddr", siaddr),
            ("giaddr", giaddr), ("chaddr", chaddr), ("sname", sname), ("file", file), ("options", options),
        ]

        for k, v in key_v: self.__dict__[k] = v

    def parse_options(self, options):
        pass


class builder(object):
    __names = None

    def __init__(self):
        pre_def_v = [
            ("op", b"\1",),
            ("htype", b"\1",),
            ("hlen", b"\6",),
            ("hops", b"\0",),
            ("xid", b"\0\0\0\0",),
            ("secs", b"\0\0",),
            ("flags", b"\0\0",),
            ("ciaddr", b"\0\0\0\0",),
            ("yiaddr", b"\0\0\0\0",),
            ("siaddr", b"\0\0\0\0",),
            ("giaddr", b"\0\0\0\0",),
            ("chaddr", bytes(16),),
            ("sname", bytes(64),),
            ("file", bytes(128)),
            ("options", b"\0"),
        ]

        self.__names = (
            "op", "htype", "hlen", "hops", "xid", "secs", "flags", "ciaddr",
            "yiaddr", "siaddr", "giaddr", "chaddr", "sname", "file", "options",
        )

        for k, v in pre_def_v: self.__dict__[k] = v

    def __setattr__(self, key, value):
        if key not in self.__dict__: raise AttributeError("cannot found property %s" % key)
        if not isinstance(value, bytes): raise TypeError("the type of value must be bytes")
        self.__dict__[key] = value

    def build(self):
        values = []
        for name in self.__names: values.append(self.__dict__[name])

        return b"".join(values)

    def build_options(self, code, length, value):
        seq = [
            chr(code).encode("iso-8859-1"),
            chr(length).encode("iso-8859-1"),
            value
        ]

        return b"".join(seq)
