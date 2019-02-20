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


def write_kern_ver_to_file(fpath):
    """写入内核版本到文件
    :param fpath:
    :return:
    """
    with open(fpath, "w") as f:
        popen = os.popen("uname -r")
        f.write(popen.read())
        popen.close()


def main():
    argv = sys.argv[1:]
    if len(argv) != 2:
        print("it is wrong argument")
        return

    __mode = argv[0]
    if __mode not in ("gateway", "server", "local"):
        print("the mode must be gateway,server or local")
        return

    py_include = argv[1]
    if not os.path.isdir(py_include):
        print("can not python3 include file")
        return

    paths = [(src_path_1, dst_path_1), (src_path_2, dst_path_2,)]

    for src, dst in paths:
        cmd = "%s %s -o %s -I %s -fPIC -shared -g -std=c99" % (
            CC, src, dst, py_include
        )
        os.system(cmd)

    if __mode == "gateway":
        os.chdir("driver")
        os.system("make clean")
        os.system("make")
        os.chdir("../")
        write_kern_ver_to_file("fdslight_etc/kern_version")

    if not os.path.isfile("driver/fdslight.ko") and __mode == "gatway":
        print("install fdslight failed!!!")
        return
    ''''''


if __name__ == '__main__':
    main()
