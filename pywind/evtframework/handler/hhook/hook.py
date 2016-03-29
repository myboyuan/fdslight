#!/usr/bin/env python3
"""实现符合handler要求的基本hook类
特殊hook说明
如果hook名字为input,那么第一个调用的就是input这个hook,如果需要input hook,请先删除原来的input hook,然后重新注册新的hook
"""


class hook(object):
    __handler = None

    def __init__(self, handler):
        self.__handler = handler

    def hook_init(self, name, *args, **kwargs):
        """重写这个方法,hook初始化
        :param name:自身的hook名
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def hook_delete(self):
        """重写这个方法,当删除hook时执行的函数
        :return:
        """
        pass

    def ctl_hook(self, name, *args, **kwargs):
        """控制其它hook,以获取状态信息等一些其它信息
        :param name:
        :param args:
        :param kwargs:
        :return:
        """
        return self.__handler.ctl_hook(name, *args, **kwargs)

    def hook_ctl(self, cmd, *args, **kwargs):
        """被其它hookt调用ctl_hook的时候将会调用这个函数
        :param cmd:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def hook_input(self, byte_data):
        """重写这个方法,接收数据
        :param byte_data:
        :return:
        """
        pass

    def hook_output(self, name, byte_data):
        """输出hook数据到其它hook
        :param name:hook名
        :param byte_data:
        :return:
        """
        self.__handler.hook_output(name, byte_data)

    def register(self, name, hook, *args, **kwargs):
        self.__handler.hook_register(name, hook, *args, **kwargs)

    def unregister(self, name):
        self.__handler.hook_unregister(name)

    def hook_exists(self, name):
        return self.__handler.hook_exists(name)

    def sys_exit(self):
        """结束这个请求"""
        self.__handler.handler_exit_from_hook()

    def wake_up(self):
        """当发生写入事件而数据并没有完全响应完毕的时候会调用这个函数
        需要在自己的handler类中手动调用此函数
        重写这个方法
        """
        pass

    def call_handler(self, name, cmd, *args, **kwargs):
        """调用handler"""
        return self.__handler.call_from_hook(name, cmd, *args, **kwargs)
