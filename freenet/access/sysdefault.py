#!/usr/bin/env python3

import freenet.access._access as _access
import os, json


class access(_access.access):
    __users = None

    def init(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../fdslight_etc/access.json" % my_dir

        all_ip4s = []
        all_ip6s = []

        self.__users = {}

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]
            ip4s = dic.get("bind_ip4s", None)
            ip6s = dic.get("bind_ip6s", None)

            if not ip4s: ip4s = []
            if not ip6s: ip6s = []

            if not isinstance(ip4s, list):
                raise ValueError("wrong configure file format for bind_ipv4")
            if not isinstance(ip6s, list):
                raise ValueError("wrong configure file format for bind_ipv6")

            # 此处检查IPv4和IPv6是否有重复
            for ip in ip4s:
                if ip in all_ip4s: raise ValueError("conflict ipv4 address %s" % ip)
            for ip in ip6s:
                if ip in all_ip6s: raise ValueError("conflict ipv6 address %s" % ip)

            all_ip4s += ip4s
            all_ip6s += ip6s
            session_id = self.gen_session_id(username, passwd)
            self.__users[session_id] = (username, ip4s, ip6s,)

    def handle_recv(self, fileno, session_id, address, data_len):
        if session_id not in self.__users: return False
        if not self.session_exists(session_id):
            username, ip4s, ip6s = self.__users[session_id]
            self.add_session(fileno, username, session_id, address, bind_ip4s=ip4s, bind_ip6s=ip6s)

        return True

    def handle_send(self, session_id, data_len):
        if not self.session_exists(session_id): return False

        return True

    def handle_close(self, session_id):
        pass

    def handle_access_loop(self):
        pass
