#!/usr/bin/env python3
import os, sys
import pywind.lib.sys_build as sys_build

# 编译器名
if sys.platform.find("freebsd") > -1:
    CC = "cc"
else:
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


def build_public_ip_client(cflags, enable_netmap=False):
    files = [
        "pywind/lib/tuntap.c",
    ]

    if sys.platform.find("linux") > -1:
        files.append(
            "pywind/clib/netif/linux_tuntap.c"
        )
    else:
        files.append(
            "pywind/clib/netif/freebsd_tuntap.c"
        )
    sys_build.do_compile(files, "freenet/lib/tuntap.so", cflags=cflags, debug=True, is_shared=True)

    if not enable_netmap: return
    sys_build.do_compile(["pywind/lib/netmap.c"], "freenet/lib/netmap.so", debug=True, is_shared=True)


def main():
    help_doc = """
    gateway | server | local | public_ip_client | public_ip_client_with_netmap  cflags
    """

    argv = sys.argv[1:]
    if len(argv) < 2:
        print("it is wrong argument")
        return

    __mode = argv[0]
    if __mode not in ("gateway", "server", "local", "public_ip_client", "public_ip_client_with_netmap",):
        print("the mode must be gateway,server or local")
        return

    if __mode.find("public_ip_client_with_netmap") > -1:
        build_public_ip_client(" " % sys.argv[1:], enable_netmap=True)
        return

    if __mode.find("public_ip_client") > -1:
        build_public_ip_client(" " % sys.argv[1:], enable_netmap=False)
        return

    paths = [(src_path_1, dst_path_1), (src_path_2, dst_path_2,)]

    for src, dst in paths:
        cmd = "%s %s -o %s %s -fPIC -shared -g -std=c99" % (
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


if __name__ == '__main__': main()
