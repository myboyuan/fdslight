#!/usr/bin/env python3
import os, sys
import pywind.lib.sys_build as sys_build


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
    sys_build.do_compile(files, "freenet/lib/tuntap.so", cflags, debug=True, is_shared=True)

    if not enable_netmap: return
    sys_build.do_compile(["pywind/lib/netmap.c"], "freenet/lib/netmap.so", cflags, debug=True, is_shared=True)


def build_server():
    pass


def build_client(cflags, gw_mode=False):
    sys_build.do_compile(
        ["freenet/lib/fn_utils.c"], "freenet/lib/fn_utils.so", cflags, debug=True, is_shared=True
    )

    sys_build.do_compile(
        ["driver/py_fdsl_ctl.c"], "freenet/lib/fdsl_ctl.so", cflags, debug=True, is_shared=True
    )

    if gw_mode:
        os.chdir("driver")
        os.system("make clean")
        os.system("make")
        os.chdir("../")
        write_kern_ver_to_file("fdslight_etc/kern_version")
        if not os.path.isfile("driver/fdslight.ko"):
            print("install fdslight failed!!!")
        ''''''


def main():
    help_doc = """
    gateway | server | local | public_ip_client | public_ip_client_with_netmap  cflags
    """

    argv = sys.argv[1:]
    if len(argv) < 2:
        print(help_doc)
        return

    mode = argv[0]

    if mode not in ("gateway", "server", "local", "public_ip_client", "public_ip_client_with_netmap",):
        print("the mode must be gateway,server or local")
        return

    if mode == "public_ip_client_with_netmap" > -1:
        build_public_ip_client(" " % sys.argv[1:], enable_netmap=True)
        return

    if mode == "public_ip_client":
        build_public_ip_client(" " % sys.argv[1:], enable_netmap=False)
        return

    if mode == "gateway":
        build_client(" " % sys.argv[1:], gw_mode=True)
        return

    if mode == "local": build_client(" " % sys.argv[1:], gw_mode=False)


if __name__ == '__main__': main()
