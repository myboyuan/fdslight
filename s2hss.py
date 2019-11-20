#!/usr/bin/env python3

import sys, os, getopt

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher

import freenet.handlers.socks2https_server as socks2https_server


class serverd(dispatcher.dispatcher):
    def init_func(self, debug=True):
        self.create_poll()

    def release(self):
        pass


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    d = None
    for k, v in opts:
        if k == "-d": d = v

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    if d == "stop":
        return

    debug = True

    if d == "start":
        debug = False

    cls = serverd()
    try:
        cls.ioloop(debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
