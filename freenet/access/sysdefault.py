#!/usr/bin/env python3

import freenet.access._access as _access
import freenet.lib.utils as utils
import os, json, socket


class access(_access.access):
    __users = None
    __bind_ip_info = None

    def load_configs(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../fdslight_etc/access.json" % my_dir

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]

            session_id = self.gen_session_id(username, passwd)

            self.__users[session_id] = username
            bind_ips = dic.get("bind_ips", [])
            if not isinstance(bind_ips, list):
                raise ValueError("wrong bind ip format from access file")

            for s in bind_ips:
                if not utils.is_ipv4_address(s) and not utils.is_ipv6_address(s):
                    raise ValueError("wrong bind ip format from access file")
                is_ipv6 = utils.is_ipv6_address(s)

                if is_ipv6:
                    fa = socket.AF_INET6
                else:
                    fa = socket.AF_INET

                byte_ip = socket.inet_pton(fa, s)
                self.set_reserve_ip(s, is_ipv6=is_ipv6)

                self.__bind_ip_info[byte_ip] = session_id

    def init(self):
        self.__users = {}
        self.__bind_ip_info = {}

        self.load_configs()

    def handle_recv(self, fileno, session_id, address, data_len):
        if session_id not in self.__users: return False
        if not self.session_exists(session_id):
            self.add_session(fileno, self.__users[session_id], session_id, address)

        return True

    def handle_send(self, session_id, data_len):
        if not self.session_exists(session_id): return False

        return True

    def handle_close(self, session_id):
        pass

    def handle_access_loop(self):
        pass

    def handle_user_change_signal(self):
        self.init()

    def get_user_bind_ip_info(self, byte_ip: bytes):
        return self.__bind_ip_info.get(byte_ip, None)
