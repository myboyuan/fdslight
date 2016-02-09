#!/usr/bin/env python3
"""
需要在配置文件加入如下项
{
...
"tunnelc_simple":{"username":username,"password":password}
...
}
"""

import json

import fdslight_etc.fn_client as fnc_config
import freenet.handler.tunnelc_base as tunnelc_base


class tcp_tunnel(tunnelc_base.tcp_tunnelc_base):
    def fn_auth_request(self):
        config = fnc_config.configs
        auth_info = config["tunnelc_simple"]

        username = auth_info["username"]
        passwd = auth_info["password"]

        return {"username": username, "password": passwd}

    def fn_auth_response(self, byte_data):
        sts = byte_data.decode("utf-8")
        try:
            pydict = json.loads(sts)
        except:
            return False
        try:
            status = pydict["status"]
        except KeyError:
            return False

        if not status:
            return False

        try:
            ips = pydict["ips"]
        except KeyError:
            return False

        try:
            aes_key = pydict["key"]
        except KeyError:
            return False

        self.encrypt_m.set_aes_key(aes_key)
        self.decrypt_m.set_aes_key(aes_key)
        self.set_virtual_ips(ips)
        return True
