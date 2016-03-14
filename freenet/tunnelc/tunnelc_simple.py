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

# 相应代码表
STATUS_AUTH_OK = 1
STATUS_SERVER_BUSY = 2
STATUS_AUTH_FAIL = 3


class tunnel(tunnelc_base.tunnelc_base):
    def fn_init(self):
        pass

    def fn_auth_request(self):
        user = fnc_config.configs["tunnelc_simple"]["username"]
        passwd = fnc_config.configs["tunnelc_simple"]["password"]

        pydict = {"user": user, "passwd": passwd}
        text = json.dumps(pydict)

        self.send_auth(text.encode())

    def fn_auth_response(self, byte_data):
        text = byte_data.decode("iso-8859-1")

        try:
            pydict = json.loads(text)
        except json.JSONDecodeError:
            return False

        status = pydict.get("status", 0)
        client_ip_list = pydict.get("alloc_ip_list")
        session_id = pydict.get("session_id", 0)
        aes_key = pydict.get("aes_key", b"")

        if status != STATUS_AUTH_OK: return False

        # 验证成功之后必须要设置session id
        self.set_session_id(session_id)

        self.alloc_vlan_ips(client_ip_list)
        self.encrypt.set_aes_key(aes_key)
        self.decrypt.set_aes_key(aes_key)

        return True
