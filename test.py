#!/usr/bin/env python3

import freenet.lib.gw as gw


def test_func(*args, **kwargs): pass


cls = gw.gw("enp0s5", "gateway", 100, 100, test_func)

print(cls.tap_fd(), cls.netmap_fd())
