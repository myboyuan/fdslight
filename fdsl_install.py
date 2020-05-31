#!/usr/bin/env python3
import os
import sys
import shutil
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
        ["driver/fdsl_dgram/py_fdsl_ctl.c"], "freenet/lib/fdsl_ctl.so", cflags, debug=True, is_shared=True
    )


def __build_gateway_module(cflags):
    files = sys_build.get_c_files("gw")
    files += [
        "freenet/lib/gw.c", "pywind/clib/netif/linux_tuntap.c", "pywind/clib/netif/linux_hwinfo.c"
    ]
    sys_build.do_compile(
        files, "freenet/lib/gw.so", cflags, debug=True, is_shared=True
    )


def build_gateway(cflags):
    __build_gateway_module(cflags)
    __build_cone_nat()


def build_tunnel_server(cflags, kern_nat_mod=False):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)

    __build_cone_nat()


def __build_cone_nat():
    """构建内核cone nat模块
    :return:
    """
    os.chdir("driver/netfilter-full-cone-nat")
    os.system("make clean")
    os.system("make")

    fname = "xt_FULLCONENAT.ko"
    fpath = "../%s" % fname

    if os.path.isfile(fpath):
        os.remove(fpath)
    if not os.path.isfile(fname):
        print("ERROR: please install linux kernel headers")
        return
    shutil.move(fname, fpath)

    os.chdir("../../")
    write_kern_ver_to_file("fdslight_etc/kern_version")


def build_tunnel_client(cflags, gw_mode=False):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)

    if gw_mode:
        __build_cone_nat()

        os.chdir("driver/fdsl_dgram")
        os.system("make clean")
        os.system("make")
        os.chdir("../../")
        write_kern_ver_to_file("fdslight_etc/kern_version")
        if not os.path.isfile("driver/fdsl_dgram/fdslight_dgram.ko"):
            print("install fdslight failed!!!")
            return

        path = "driver/fdslight_dgram.ko"
        if os.path.isfile(path):
            os.remove(path)
        shutil.move("driver/fdsl_dgram/fdslight_dgram.ko", "driver")


def main():
    help_doc = """
    tunnel_gw | tunnel_server | tunnel_local | gateway   python3_include
    """

    argv = sys.argv[1:]
    if len(argv) != 2:
        print(help_doc)
        return

    mode = argv[0]

    if mode not in ("tunnel_gw", "tunnel_server", "tunnel_local", "gateway",):
        print("the mode must be tunnel_gw,tunnel_server,tunnel_local,gateway")
        return

    if not os.path.isdir(argv[1]):
        print("not found directory %s" % argv[1])
        return

    cflags = " -I %s" % "".join(argv[1:])

    if mode == "tunnel_gw":
        build_tunnel_client(cflags, gw_mode=True)
        return

    if mode == "tunnel_server":
        build_tunnel_server(cflags)
        return

    if mode == "tunnel_local":
        build_tunnel_client(cflags, gw_mode=False)
        return

    if mode == "gateway":
        build_gateway(cflags)


if __name__ == '__main__':
    main()
