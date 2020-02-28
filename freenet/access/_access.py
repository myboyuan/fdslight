#!/usr/bin/env python3
import pywind.lib.timer as timer
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.logging as logging


class access(object):
    __timer = None
    __sessions = None
    # 会话超时时间
    __SESSION_TIMEOUT = 800

    __dispatcher = None

    # ipv4到session id的映射
    __ipv4_to_session_id = None
    # ipv6到session id的映射
    __ipv6_to_session_id = None

    def __init__(self, dispatcher):
        self.__timer = timer.timer()
        self.__sessions = {}
        self.__dispatcher = dispatcher
        self.__ipv4_to_session_id = {}
        self.__ipv6_to_session_id = {}

        self.init()

    def init(self):
        """初始化函数,重写这个方法"""
        pass

    def handle_recv(self, fileno, session_id, address, data_len):
        """处理数据的接收
        :param session_id,会话ID
        :param address,用户地址
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

    def handle_access_loop(self):
        """此函数会被循环调用,重写这个方法"""
        pass

    def handle_close(self, session_id):
        """处理会话关闭"""
        pass

    def add_session(self, fileno, username, session_id, address, bind_ip4s=None, bind_ip6s=None, priv_data=None):
        """加入会话
        :param fileno:文件描述符
        :param username:用户名
        :param session_id: 会话ID
        :param address: (ipaddr,port)
        :param bind_ip4s,给客户端分配的公共IP地址,类型为列表
        :param bind_ip6s:给客户端分配的公共IPv6地址,类型为列表
        :param priv_data:你的私有数据,如果想要修改数据,priv_data应该是引用类型
        :return:
        """
        if self.session_exists(session_id): return

        for ip in bind_ip4s:
            self.__ipv4_to_session_id[ip] = session_id
        for ip in bind_ip6s:
            self.__ipv6_to_session_id[ip] = session_id

        self.__sessions[session_id] = [fileno, username, address, bind_ip4s, bind_ip6s, priv_data, ]
        self.__timer.set_timeout(session_id, self.__SESSION_TIMEOUT)
        self.__dispatcher.tell_register_session(session_id)

        logging.print_general("add_session:%s" % username, address)

    def get_session_info(self, session_id):
        if session_id not in self.__sessions: return None

        return tuple(self.__sessions[session_id])

    def del_session(self, session_id):
        """删除会话
        :param session_id:
        :return:
        """
        if session_id not in self.__sessions: return

        self.__timer.drop(session_id)
        self.handle_close(session_id)
        fileno, username, address, bind_ip4s, bind_ip6s, priv_data = self.__sessions[session_id]
        self.__dispatcher.tell_unregister_session(session_id, fileno)

        logging.print_general("del_session:%s" % username, address)

        for ip in bind_ip4s:
            del self.__ipv4_to_session_id[ip]
        for ip in bind_ip6s:
            del self.__ipv6_to_session_id[ip]

        del self.__sessions[session_id]

    def modify_session(self, session_id, fileno, address):
        """修改地址和文件描述符信息,如果没有变化则不修改
        :param session_id:
        :param address:
        :return:
        """
        a = "%s-%s" % address
        b = "%s-%s" % (self.__sessions[session_id][2])

        if a != b:
            self.__sessions[session_id][2] = address
        self.__sessions[session_id][0] = fileno

    def session_exists(self, session_id):
        return session_id in self.__sessions

    def gen_session_id(self, username, password):
        """生成用户session id
        :param username:
        :param password:
        :return:
        """
        return proto_utils.gen_session_id(username, password)

    def access_loop(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.del_session(name)
        return

    def data_for_send(self, session_id, pkt_len):
        b = self.handle_send(session_id, pkt_len)
        if b: self.__timer.set_timeout(session_id, self.__SESSION_TIMEOUT)

        return b

    def data_from_recv(self, fileno, session_id, address, pkt_len):
        b = self.handle_recv(fileno, session_id, address, pkt_len)

        if b:
            self.modify_session(session_id, fileno, address)
        return b

    def get_session_id_for_ip(self, ip, is_ipv6=False):
        """根据IP地址获取用户会话ID
        :param ip:
        :param is_ipv6:
        :return:
        """
        if is_ipv6:
            dic = self.__ipv6_to_session_id
        else:
            dic = self.__ipv4_to_session_id

        return dic.get(ip, None, )
