#!/usr/bin/env python3
import os, sys

# 编译器名
CC = "gcc"
# Python的包含路径
py_include = ""
src_path = "freenet/lib/fn_utils.c"
dst_path = "freenet/lib/fn_utils.so"


def main():
    argv = sys.argv[1:]
    if len(argv) != 1:
        print("it is wrong argument")
        return

    py_include = argv[0]
    if not os.path.isdir(py_include):
        print("can not python3 include file")
        return

    cmd = "%s %s -o %s -I %s -fPIC -shared -std=c99" % (
        CC, src_path, dst_path, py_include
    )

    os.system(cmd)


if __name__ == '__main__':
    main()
