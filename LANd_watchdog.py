#!/usr/bin/env python3
"""LANd_pass的看门狗程序
"""
import sys, os, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

LAN_PID_PATH = "/tmp/LANd.pid"


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("wrong argument")
        return

    pid = os.fork()
    if pid != 0: sys.exit(0)

    os.setsid()
    os.umask(0)

    pid = os.fork()
    if pid != 0: sys.exit(0)

    while 1:
        if not os.path.isfile(LAN_PID_PATH):
            cmd = "%s %s/LANd_pass.py %s %s" % (sys.argv[1], BASE_DIR, sys.argv[2], sys.argv[3])
            os.system(cmd)
        time.sleep(60)


if __name__ == '__main__': main()
