#!/usr/bin/env python3
# 进程间消息协议
"""
src_pid: 4 bytes 源进程号
dst_pid: 4 bytes 目标进程号
src_file: 4bytes 源文件描述符
dst_file: 4 bytes 目标文件描述符
payload: 2 bytes 数据长度
"""
import pywind.evtframework.handler.tcp_handler as tcp_handler


class process_msg(tcp_handler.tcp_handler):
    def init_func(self, skt):
        self.set_socket(skt)

        return self.fileno

    def __process_msg_register(self, pid):
        """向所在的父进程注册自己的进程号"""
        pass

    def __process_msg_unregister(self, pid):
        """ 取消消息注册
        :param pid:
        :return:
        """
        pass

    def __send_process_msg(self, src_pid, dst_pid, src_fd, dst_fd, message):
        """
        :param src_pid: 源进程id
        :param dst_pid: 目标进程id
        :param message: 消息内容
        :return:
        """
        pass

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        pass

    def message_from_other_process(self, src_pid, src_fd, message):
        """接收其它消息过来的进程消息
        :param src_pid:
        :param message:
        :return:
        """
        pass

    def message_from_handler(self, from_fd, byte_data):
        pass
