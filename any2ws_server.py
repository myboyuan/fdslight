#!/usr/bin/env python3

import sys, os, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import any2ws.handlers.any2tcp as any2tcp
import any2ws.handlers.client as client
import any2ws.any2wsd as any2wsd

PID_PATH = "%s/any2ws_server.pid" % BASE_DIR


class any2wsd_server(any2wsd.any2wsd):
    def any2ws_init(self):
        self.set_sysroot(BASE_DIR)

    def any2ws_release(self):
        pass

    @property
    def conn_timeout(self):
        return 300


def main():
    rs = any2wsd.parse_syargv()
    if not rs: return

    if rs == "stop":
        pid = any2wsd.read_pid_from_file(PID_PATH)
        os.kill(pid, signal.SIGINT)
        return

    if rs == "start":
        pid = os.fork()
        if pid != 0: sys.exit(0)
        os.setsid()
        os.umask(0)
        pid = os.fork()
        if pid != 0: sys.exit(0)

    cls_obj = any2wsd_server()

    try:
        cls_obj.ioloop()
    except KeyboardInterrupt:
        cls_obj.any2ws_release()
        return


if __name__ == '__main__': main()
