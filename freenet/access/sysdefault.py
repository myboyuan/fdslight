#!/usr/bin/env python3

import freenet.access._access as _access
import freenet.lib.utils as utils
import os, json


class access(_access.access):
    __users = None

    __bind_ips = None

    def init(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../fdslight_etc/access.json" % my_dir
        self.__bind_ips = {}

        self.__users = {}

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]

            bind_ips = dic.get("bind_ips", [])
            if not isinstance(bind_ips, list):
                raise ValueError("wrong access.json file at %s" % str(dic))
            session_id = self.gen_session_id(username, passwd)

            self.handle_bind_ips(session_id, bind_ips)
            self.__users[session_id] = username

    def handle_bind_ips(self, session_id, ip_list):
        for ip in ip_list:
            if not utils.is_ipv4_address(ip) and not utils.is_ipv6_address(ip):
                raise ValueError("wrong ip address format at access.json %s" % ip)
            if ip in self.__bind_ips:
                raise ValueError("conflict ip address about %s" % ip)
            self.__bind_ips[ip] = session_id

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

    def get_user_info_for_bind_ip(self, ip_addr):
        session_id = self.__bind_ips.get(ip_addr, None)
        if session_id:
            return (True, session_id,)
        return (False, session_id,)
