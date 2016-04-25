#!/usr/bin/env python3
import freenet.handler.tunnels_tcp_base as tunnels_base
import freenet.lib.utils as utils
import fdslight_etc.fn_server as fns_config
import json


class tunnel(tunnels_base.tunnels_tcp_base):
    def __response_auth_fail(self, spec=""):
        self.send_auth(json.dumps({"status": False, "spec": spec}).encode())

    def fn_auth(self, byte_data):
        try:
            sts = byte_data.decode()
        except UnicodeDecodeError:
            self.__response_auth_fail(spec="wrong data auth format")
            return False
        try:
            pyobj = json.loads(sts)
        except json.JSONDecodeError:
            self.__response_auth_fail(spec="wrong data auth format")
            return False
        if not (type(pyobj) is dict):
            self.__response_auth_fail(spec="it is not json type")
            return False
        keys = ("username", "passwd",)
        for key in keys:
            if key not in pyobj:
                self.__response_auth_fail(spec="the json property incomplete")
                return False
            ''''''

        ulist = fns_config.configs["tunnels_simple"]
        username = pyobj["username"]
        passwd = pyobj["passwd"]
        auth_ok = False

        for u, p in ulist:
            if u == username and passwd == p:
                auth_ok = True
                break
            ''''''
        if not auth_ok:
            self.__response_auth_fail()
            return False
        vlan_ips = self.get_alloc_vlan_ips(5)
        if not vlan_ips:
            self.__response_auth_fail(spec="not enough ip address")
            return False
        key = utils.rand_string(16)
        pydict = {
            "status": True,
            "vlan_ips": vlan_ips,
            "key": key
        }
        self.__allocated_vlan_ips = vlan_ips
        self.send_auth(json.dumps(pydict).encode())

        # 一定要先发送数据然后设置新的key,不然收到的数据就是新的key加密,导致客户端收到的数据是错的
        self.encrypt.set_aes_key(key)
        self.decrypt.set_aes_key(key)
        return True

    def fn_recv(self, pkt_len):
        return True

    def fn_send(self, pkt_len):
        return True

    def fn_close(self):
        pass
