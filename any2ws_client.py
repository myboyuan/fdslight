#!/usr/bin/env python3

import os, signal, sys

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import any2ws.handlers.any2tcp as any2tcp
import any2ws.any2wsd as any2wsd

PID_PATH = "%s/any2ws_client.pid" % BASE_DIR


class any2wsd_client(any2wsd.any2wsd):
    __any2ws_listen_fileno = None
    __any2ws_listen6_fileno = None

    def create_listener(self):
        local_configs = self.configs.get("local", {})

        enable_ipv6 = bool(int(local_configs.get("enable_ipv6", 0)))
        listen_ip = local_configs.get("listen_ip", "0.0.0.0")
        listen_ipv6 = local_configs.get("listen_ipv6", "::")
        listen_port = int(local_configs.get("listen_port", 8000))

        if enable_ipv6:
            self.__any2ws_listen6_fileno = self.create_handler(-1, any2tcp.listener, (listen_ipv6, listen_port,),
                                                               is_ipv6=True)

            self.get_handler(self.__any2ws_listen6_fileno).after()

        self.__any2ws_listen_fileno = self.create_handler(-1, any2tcp.listener, (listen_ip, listen_port,),
                                                          is_ipv6=False)
        self.get_handler(self.__any2ws_listen_fileno).after()

    def any2ws_init(self):
        self.set_sysroot(BASE_DIR)
        self.__any2ws_listen_fileno = -1
        self.__any2ws_listen6_fileno = -1

        self.load_configs("client.ini")
        self.create_listener()

    def any2ws_release(self):
        pass


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
        any2wsd.write_pid_to_file(PID_PATH)

    cls_obj = any2wsd_client()

    try:
        cls_obj.ioloop()
    except KeyboardInterrupt:
        cls_obj.any2ws_release()

    if os.path.isfile(PID_PATH): os.remove(PID_PATH)


if __name__ == '__main__': main()
