#!/usr/bin/env python3

import freenet.handler.tunnelc_tcp_base as tunnelc_base
import fdslight_etc.fn_client as fnc_config
import json


class tunnel(tunnelc_base.tunnelc_tcp_base):
    def fn_auth_request(self):
        auth_info = fnc_config.configs["tunnelc_simple"]
        username = auth_info["username"]
        password = auth_info["password"]

        auth_req = json.dumps({"username": username, "passwd": password}).encode()
        self.send_auth(auth_req)

    def fn_auth_response(self, byte_data):
        sts = byte_data.decode()
        pyobj = json.loads(sts)

        if not pyobj["status"]: return False

        aes_key = pyobj["key"]

        self.encrypt.set_aes_key(aes_key)
        self.decrypt.set_aes_key(aes_key)
        self.alloc_vlan_ips(pyobj["vlan_ips"])

        return True

    def fn_close(self):
        pass
