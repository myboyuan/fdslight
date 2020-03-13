#!/usr/bin/env python3

import freenet.access._access as _access
import freenet.lib.utils as utils
import os, json, socket


class access(_access.access):
    __users = None

    __bind_ips = None

    def load_configs(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../fdslight_etc/access.json" % my_dir

        mapv = {}

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]

            bind_ip = dic.get("bind_ip", None)
            bind_ip6 = dic.get("bind_ip6", None)

            if bind_ip and utils.is_ipv4_address(bind_ip):
                raise ValueError("wrong ip address at %s" % bind_ip)
            if bind_ip6 and utils.is_ipv6_address(bind_ip6):
                raise ValueError("wrong ipv6 address at %s" % bind_ip6)

            session_id = self.gen_session_id(username, passwd)

            if bind_ip:
                if bind_ip in mapv: raise ValueError("conflict ip adress %s" % bind_ip)
                byte_bind_ip = socket.inet_pton(socket.AF_INET, bind_ip)
                mapv[byte_bind_ip] = (session_id, False,)
            if bind_ip6:
                if bind_ip6 in mapv: raise ValueError("conflict ipv6 address %s" % bind_ip6)
                byte_bind_ip6 = socket.inet_pton(socket.AF_INET6, bind_ip)
                mapv[byte_bind_ip6] = (session_id, True,)

            self.__users[session_id] = username

        self.modify_pub_ip(mapv)

    def modify_pub_ip(self, mapv):
        adds = []
        dels = []

        # 旧的绑定新的没有那么需要删除
        for ip in self.__bind_ips:
            if ip not in mapv: dels.append((ip, utils.is_ipv6_address(ip),))

        for ip in mapv:
            r = mapv[ip]
            if ip not in self.__bind_ips: adds.append((ip, r[1],))
            self.__bind_ips[ip] = r[0]

        for ip, is_ipv6 in adds:
            if is_ipv6:
                prefix = 128
                fa = socket.AF_INET6
            else:
                prefix = 32
                fa = socket.AF_INET

            s_ip = socket.inet_ntop(fa, ip)
            self.set_route(s_ip, prefix, is_ipv6=is_ipv6)

        for ip, is_ipv6 in dels:
            if is_ipv6:
                prefix = 128
                fa = socket.AF_INET6
            else:
                prefix = 32
                fa = socket.AF_INET

            s_ip = socket.inet_ntop(fa, ip)
            self.del_route(s_ip, prefix, is_ipv6=is_ipv6)

    def init(self):
        self.__bind_ips = {}
        self.__users = {}

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

    def get_user_info_for_bind_ip(self, byte_ip_addr):
        session_id = self.__bind_ips.get(byte_ip_addr, None)
        if session_id:
            return (True, session_id,)
        return (False, session_id,)

    def handle_user_change_signal(self):
        self.load_configs()
