#!/usr/bin/env python3
"""此文件用于唤醒局域网内的机器
"""
import sys, os, json, getopt, socket

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.wol as wol
import freenet.lib.cfg_check as cfg_check


def get_machines():
    cfg_path = "%s/fdslight_etc/wakeup_machines.json" % BASE_DIR

    if not os.path.isfile(cfg_path):
        sys.stderr.write("not found configure file %s\r\n" % cfg_path)
        return None

    with open(cfg_path) as f:
        s = f.read()
    f.close()
    o = json.loads(s)

    for k, v in o.items():
        rs = wol.mac2byte(v)
        if not rs:
            sys.stderr.write("wrong mac address from name %s\r\n" % k)
            return None

    return o


def wake_up_direct():
    """直接唤醒而不是通过互联网
    :return:
    """
    o = get_machines()
    if None == o: return

    cls = wol.wake_on_lan()
    for k, v in o.items():
        cls.wake(v)
    cls.release()
    print("send wake up ok")

def main():
    help_doc = """
    direct                send packet to LAN
    """
    if len(sys.argv) < 2:
        print(help_doc)
        return

    _type = sys.argv[1]

    if _type not in ("direct",):
        print(help_doc)
        return

    if _type == "direct":
        wake_up_direct()
        return

if __name__ == '__main__': main()
