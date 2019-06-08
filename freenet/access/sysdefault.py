#!/usr/bin/env python3

import freenet.access._access as _access
import os, json


class access(_access.access):
    __users = None

    def init(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../fdslight_etc/access.json" % my_dir

        self.__users = {}

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]

            session_id = self.gen_session_id(username, passwd)
            print("--",session_id)
            self.__users[session_id] = username

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
