#!/usr/bin/env python3

from pywind.global_vars import global_vars
import pywind.evtframework.consts as consts


class handler(object):
    __hooks = None
    __fileno = -1

    def __init__(self):
        self.__hooks = {}

    def set_fileno(self, fd):
        """设置这个处理者所对应的fd"""
        self.__fileno = fd

    @property
    def fileno(self):
        return self.__fileno

    def init_func(self, creator_fd, *args, **kwargs):
        """初始化函数,当对象实例后框架调用的函数
        :param creator_fd:创建者文件描述符
        :return fd:文件描述符,注意此描述符必须唯一
        """
        pass

    def delete_hooks(self):
        """根据需要重写这个方法,注意要调用父类 delete_hooks"""
        for hk_name in self.__hooks:
            hk = self.__hooks[hk_name]
            hk.hook_delete()

        self.__hooks = None

    def delete_hook(self, hook_name):
        """根据需要重写这个方法,注意要调用父类 delete_hook"""
        hk = self.__hooks.get(hook_name, None)
        if not hk:
            return
        hk.hook_delete()
        del self.__hooks[hook_name]

    def hook_register(self, name, hook, *args, **kwargs):
        """注册handler的hook
        :param name:
        :param hook:
        :return:
        """
        if name in self.__hooks:
            return False

        instance = hook(self)
        self.__hooks[name] = instance

        instance.hook_init(*args, **kwargs)

        return True

    def hook_unregister(self, name):
        """取消handler中的hook
        :param name:
        :return:
        """
        if name not in self.__hooks:
            return

        hk = self.__hooks[name]
        hk.hook_delete()

    def hook_exists(self, name):
        return name in self.__hooks

    def get_hook(self, name):
        hk = None

        try:
            hk = self.__hooks[name]
        except KeyError:
            pass
        return hk

    def ctl_hook(self, name, cmd, *args, **kwargs):
        hk = self.__hooks[name]

        return hk.hook_ctl(cmd, *args, **kwargs)

    def hook_input(self, name, byte_data):
        """向hook输入数据,重写这个方法
        :param byte_data:
        :return:
        """
        self.__hooks[name].hook_input(byte_data)

    def hook_output(self, name, byte_data):
        """输出hook数据,重写这个方法
        :param byte_data:
        :return:
        """
        pass

    def evt_read(self):
        """读事件,重写这个方法
        :return:
        """
        pass

    def evt_write(self):
        """写事件,重写这个方法
        :return:
        """
        pass

    def timeout(self):
        """时间超时,重写这个方法
        :return:
        """
        pass

    def error(self):
        """故障,重写这个方法
        :return:
        """
        pass

    def delete(self):
        """最一些对象销毁的善后工作,重写这个方法
        :return:
        """
        pass

    def set_timeout(self, fd, seconds):
        self.dispatcher.set_timeout(fd, seconds)

    def create_handler(self, creator_fd, h, *args, **kwargs):
        return self.dispatcher.create_handler(creator_fd, h, *args, **kwargs)

    def delete_handler(self, fd):
        self.dispatcher.delete_handler(fd)

    def send_message_to_handler(self, src_fd, dst_fd, byte_data):
        return self.dispatcher.send_message_to_handler(src_fd, dst_fd, byte_data)

    def message_from_handler(self, from_fd, byte_data):
        """重写这个方法,当其他的处理者发送消息会调用这个函数
        :return:
        """
        pass

    def handler_exists(self, fd):
        return self.dispatcher.handler_exists(fd)

    def register(self, fd):
        self.dispatcher.register(fd)

    def add_evt_read(self, fd):
        self.dispatcher.add_evt_read(fd)

    def remove_evt_read(self, fd):
        self.dispatcher.remove_evt_read(fd)

    def add_evt_write(self, fd):
        self.dispatcher.add_evt_write(fd)

    def remove_evt_write(self, fd):
        self.dispatcher.remove_evt_write(fd)

    def unregister(self, fd):
        self.dispatcher.unregister(fd)

    @property
    def dispatcher(self):
        """获取分发器
        :return:
        """
        return global_vars[consts.SERVER_INSTANCE_NAME]

    def reset(self):
        """重置资源,用于实现对象的重复利用,重写这个方法
        :return:
        """
        pass

    def ctl_handler(self, src_fd, dst_fd, cmd, *args, **kwargs):
        """控制其它handler的行为
        :param dst_fd:
        :param cmd:
        :param args:
        :param kwargs:
        :return:
        """
        return self.dispatcher.ctl_handler(src_fd, dst_fd, cmd, *args, **kwargs)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        """handler控制命令,当此其它handler需要控制此handler的时候,此函数将会被调用
        :param dst_fd:
        :param cmd:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def handler_ctl_from_hook(self,from_hook,cmd,*args,**kwargs):
        """接收hook的控制命令,重写这个方法"""
        pass