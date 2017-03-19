#!/usr/bin/env python3

import freenet.lib.fn_utils as utils

cls=utils.mbuf()
cls.copy2buf(b"hello")

cls[0]=100
print(cls[0])