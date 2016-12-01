#!/usr/bin/env python3
import os, sys

# 编译器名
CC = "gcc"
# Python开发包包含路径
py_include = ""
src_path_1 = "freenet/lib/fn_utils.c"
src_path_2 = "driver/py_fdsl_ctl.c"
dst_path_1 = "freenet/lib/fn_utils.so"
dst_path_2 = "freenet/lib/fdsl_ctl.so"

__mode = "gateway"

def main():
    argv = sys.argv[1:]
    if len(argv) != 2:
        print("it is wrong argument")
        return

    __mode = argv[0]
    if __mode not in ("gateway", "server",):
        print("the mode must be gateway or server")
        return

    py_include = argv[1]
    if not os.path.isdir(py_include):
        print("can not python3 include file")
        return

    paths = [(src_path_1, dst_path_1), (src_path_2, dst_path_2,)]

    for src, dst in paths:
        cmd = "%s %s -o %s -I %s -fPIC -shared -std=c99" % (
            CC, src, dst, py_include
        )
        os.system(cmd)

    if __mode == "client":
        os.chdir("driver")
        os.system("make")

    if not os.path.isfile("fdslight.ko") and __mode == "client":
        print("install fdslight failed!!!")
        return
    ''''''


if __name__ == '__main__':
    main()
