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


def __build_fn_utils(cflags):
    sys_build.do_compile(
        ["freenet/lib/fn_utils.c"], "freenet/lib/fn_utils.so", cflags, debug=True, is_shared=True
    )


def __build_fdsl_ctl(cflags):
    sys_build.do_compile(
        ["driver/py_fdsl_ctl.c"], "freenet/lib/fdsl_ctl.so", cflags, debug=True, is_shared=True
    )


def build_server(cflags):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)


def build_client(cflags, gw_mode=False):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)

    if gw_mode:
        os.chdir("driver")
        os.system("make clean")
        os.system("make")
        os.chdir("../")
        write_kern_ver_to_file("fdslight_etc/kern_version")
        if not os.path.isfile("driver/fdslight_dgram.ko"):
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

    if mode not in ("gateway", "server", "local", "public_ip_client",):
        print("the mode must be gateway,server or local")
        return

    cflags = " -I %s" % "".join(argv[1:])

    if mode == "gateway":
        build_client(cflags, gw_mode=True)
        return

    if mode == "server":
        build_server(cflags)
        return

    if mode == "local": build_client(cflags, gw_mode=False)


if __name__ == '__main__': main()
