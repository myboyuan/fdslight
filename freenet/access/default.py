#!/usr/bin/env python3
"""
默认的验证模块,配置文件为default_auth.json
"""

import json, os
import freenet.access._access as auth_base
import freenet.lib.base_proto.utils as proto_utils


class auth(auth_base.auth):
    __sessions = None

    def init(self):
        self.__sessions = {}
        dirname = os.path.dirname(__file__)
        path = "%s/../../fdslight_etc/default_auth.json" % dirname

        with open(path, "r") as f:
            data = f.read()

        user_info = json.loads(data)
        for user in user_info:
            name = user["username"]
            passwd = user["password"]

            session_id = proto_utils.gen_session_id(name, passwd)
            self.__sessions[session_id] = None
        return

    def handle_recv(self, session_id, data_len):
        if session_id not in self.__sessions: return False
        return True

    def handle_send(self, session_id, data_len):
        if session_id not in self.__sessions: return False
        return True

    def handle_timing_task(self, session_id):
        pass

    def handle_close(self, session_id):
        pass
