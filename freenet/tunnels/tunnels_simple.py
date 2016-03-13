#!/usr/bin/env python3
"""
最简单的tunnel server,采用默认的aes128加密
配置文件添加一个字段tunnels_simple
最终形式例如这样
{
...
tunnels_simple:[
    (username,passwd),....
]
...
}

"""

import freenet.handler.tunnels_base as tunnels_base
import freenet.lib.base_proto.tunnel as protocol
import fdslight_etc.fn_server as fns_config
import json, random

# 相应代码表
STATUS_AUTH_OK = 1
STATUS_SERVER_BUSY = 2
STATUS_AUTH_FAIL = 3


class tunnel(tunnels_base.tunnels_base):
    __session_info = None
    __session_limit = None

    def __rand_key(self, length=16):
        """生成随机KEY"""
        sts = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        size = len(sts)
        tmplist = []
        for i in range(length):
            n = random.randint(0, size - 1)
            tmplist.append(
                sts[n]
            )

        return "".join(tmplist)

    def __response(self, code, address, session_id=0, aes_key=None, client_ips=None):
        pydict = {
            "status": code,
            "alloc_ip_list": client_ips,
            "session_id": session_id,
            "aes_key": aes_key,
        }
        text = json.dumps(pydict)
        byte_data = text.encode()

        self.send_auth(address, byte_data)

        # 一定要在发送验证之后再重新设定aes key
        if aes_key:
            b_aes_key = aes_key.encode()
            self.get_encrypt(address).set_aes_key(b_aes_key)
            self.get_decrypt(address).set_aes_key(b_aes_key)
        return

    def fn_init(self):
        self.__session_info = {}
        self.__session_limit = {}

    def fn_auth(self, byte_data, address):
        """
        :param byte_data:
        :param address:
        :return:
        """
        uniq_id = "%s-%s" % address

        # 重要:由于UDP的无状态性,为了确保验证包能收到,可能同时会发送多个验证,或者验证顺序错乱,因此需要处理
        if uniq_id in self.__session_info:
            session_id, client_ips, username = self.__session_info[uniq_id]
            self.__response(STATUS_AUTH_OK, address,
                            session_id=session_id,
                            aes_key=self.__rand_key(),
                            client_ips=client_ips
                            )
            return True

        text = byte_data.decode("iso-8859-1")
        try:
            pydict = json.loads(text)
        except json.JSONDecodeError:
            return False

        username = pydict.get("user", "")
        passwd = pydict.get("passwd", "")

        is_find = False
        users_info = fns_config.configs["tunnels_simple"]

        for u, p in users_info:
            if u == username and passwd == p:
                is_find = True
                break
            ''''''

        # 默认有5台机器可以同时在线
        if is_find:
            # 重要：防止一个用户有多个连接,占用服务器的虚拟IP资源
            if username in self.__session_limit:
                # 获取旧的地址
                old_address = self.__session_limit[username]
                # 释放session
                self.unregister_session(old_address)

            client_ips = self.get_client_ips(5)
            if not client_ips:
                self.__response(STATUS_SERVER_BUSY, address)
                return False
            session_id = self.register_session(address, client_ips)
            if not session_id:
                self.__response(STATUS_SERVER_BUSY, address)
                return False
            aes_key = self.__rand_key()
            self.__response(STATUS_AUTH_OK, address, session_id=session_id, aes_key=aes_key, client_ips=client_ips)
            self.__session_info[uniq_id] = (session_id, client_ips, username,)
            self.__session_limit[username] = address
        else:
            self.__response(STATUS_AUTH_FAIL, address)

        return is_find

    def fn_recv(self, data_len, address):
        return True

    def fn_send(self, data_len, address):
        return True

    def fn_delete(self, address):
        uniq_id = "%s-%s" % address
        session_id, client_ips, username = self.__session_info[uniq_id]

        del self.__session_limit[username]
