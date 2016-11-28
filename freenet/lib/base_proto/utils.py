#!/usr/bin/env python3
import hashlib

class ProtoError(Exception): pass

def calc_content_md5(content):
    md5 = hashlib.md5()
    md5.update(content)

    return md5.digest()
