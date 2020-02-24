#!/usr/bin/env python3

import sys, os, getopt

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import freenet.handlers.relay as relay
import freenet.lib.utils as utils


class service(dispatcher.dispatcher):
    __listen_fd = None

    def init_func(self, bind, redirect, is_ipv6=False, force_ipv6=False):
        self.__listen_fd = -1
        self.create_poll()
        self.__listen_fd = self.create_handler(-1, relay.tcp_listener, bind, redirect, listen_is_ipv6=is_ipv6,
                                               relay_is_ipv6=force_ipv6)

    def release(self):
        if self.__listen_fd > 0: self.delete_handler(self.__listen_fd)


def main():
    help_doc = """
    --bind=address,port --redirect=host,port [-6] [--nofork]
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "-6", ["nofork", "bind=", "redirect=", "help"])
    except getopt.GetoptError:
        print(help_doc)
        return

    bind = None
    redirect = None
    force_ipv6 = False

    bind_s = None
    redirect_s = None
    fork = True
    is_ipv6 = False

    for k, v in opts:
        if k == "-6": force_ipv6 = True
        if k == "--bind": bind_s = v
        if k == "--redirect": redirect_s = v
        if k == "--help":
            print(help_doc)
            return
        if k == "--nofork": fork = False

    if not bind_s:
        print("please set bind address")
        return

    if not redirect_s:
        print("please set redirect address")
        return

    seq = bind_s.split(",")
    if len(seq) != 2:
        print("wrong bind address format")
        return

    try:
        bind = (seq[0], int(seq[1]),)
    except ValueError:
        print("wrong bind address format")
        return

    if bind[1] > 0xffff - 1 or bind[1] < 1:
        print("wrong bind port number")
        return

    if not utils.is_ipv6_address(bind[0]) and (not utils.is_ipv4_address(bind[0])):
        print("please set bind address")
        return

    if utils.is_ipv6_address(bind[0]): is_ipv6 = True

    seq = redirect_s.split(",")
    if len(seq) != 2:
        print("wrong redirect address format")
        return

    try:
        redirect = (seq[0], int(seq[1]),)
    except ValueError:
        print("wrong redirect address format")
        return

    if fork:
        pid = os.fork()
        if pid != 0: sys.exit(0)
        os.umask(0)
        os.setsid()
        pid = os.fork()
        if pid != 0: sys.exit(0)

    instance = service()
    try:
        instance.ioloop(bind, redirect, force_ipv6=force_ipv6)
    except KeyboardInterrupt:
        instance.release()


if __name__ == '__main__': main()
