#!/usr/bin/env python3
import pywind.lib.timer as timer


class access(object):
    __timer = None
    __sessions = None

    def __init__(self):
        self.__timer = timer.timer()
        self.__sessions = {}

    def init(self):
        """初始化函数,重写这个方法"""
        pass

    def handle_recv(self, session_id, data_len):
        """处理数据的接收
        :param session_id,会话ID
        :param data_len,数据长度
        :return Boolean,True表示允许接受数据,False表示抛弃数据
        """
        return True

    def handle_send(self, session_id, data_len):
        """处理数据的发送
        :param session_id,会话ID
        :param data_len,数据长度
        :return Boolean,True表示允许发送数据,False表示抛弃数据
        """
        return True

    def access_loop(self):
        """此函数会被循环调用,重写这个方法"""
        pass

    def handle_close(self, session_id):
        """处理会话关闭"""
        pass

    def add_session(self, session_id, address, priv_data=None):
        """加入会话
        :param session_id: 会话ID
        :param address: (ipaddr,port)
        :param priv_data:你的私有数据,如果想要修改数据,priv_data应该是引用类型
        :return:
        """
        if self.session_exists(session_id): return

        self.__sessions[session_id] = [address, priv_data, ]

    def get_session_info(self, session_id):
        if session_id not in self.__sessions: return None

        return tuple(self.__sessions[session_id])

    def del_session(self, session_id):
        """删除会话
        :param session_id:
        :return:
        """
        pass

    def modify_client_address(self, session_id, address):
        """修改地址信息,如果没有变化则不修改
        :param session_id:
        :param address:
        :return:
        """
        pass

    def session_exists(self, session_id):
        return session_id in self.__sessions
