#!/usr/bin/env python3

import any2ws.handlers.any2tcp as any2tcp
import any2ws.any2wsd as any2wsd


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
        self.load_configs()
        self.__any2ws_listen_fileno = -1
        self.__any2ws_listen6_fileno = -1

        self.create_listener()

    def any2ws_release(self):
        pass


def main():
    rs = any2wsd.parse_syargv()
    if not rs: return



if __name__ == '__main__': main()
