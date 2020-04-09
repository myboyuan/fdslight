#!/usr/bin/env python3
"""LANd_pass的看门狗程序
"""
import sys, os, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

LAN_PID_PATH = "/tmp/LANd.pid"


def main():
    flags = False

    if len(sys.argv) != 5:
        sys.stderr.write("wrong argument\r\n")
        return

    pid = os.fork()
    if pid != 0: sys.exit(0)

    os.setsid()
    os.umask(0)

    pid = os.fork()
    if pid != 0: sys.exit(0)

    while 1:
        if not os.path.isfile(LAN_PID_PATH):
            cmd = "%s %s/LANd_pass.py start %s %s %s" % (sys.argv[1], BASE_DIR, sys.argv[2], sys.argv[3], sys.argv[4])
            # 第一次执行的时候打印命令
            if not flags:
                flags = True
                print(cmd)
            os.system(cmd)
            # 进程启动以及生成pid文件需要时间,因此这里需要休眠
            time.sleep(60)
        time.sleep(60)


if __name__ == '__main__': main()
