#!/usr/bin/env python3

class auth(object):
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

    def handle_send(self,session_id,data_len):
        """处理数据的发送
        :param session_id,会话ID
        :param data_len,数据长度
        :return Boolean,True表示允许发送数据,False表示抛弃数据
        """
        return True

    def handle_timing_task(self,session_id):
        """处理定时任务,这个函数每隔一段时间会自动调用一次"""
        pass

    def handle_close(self,session_id):
        """处理会话关闭"""
        pass
