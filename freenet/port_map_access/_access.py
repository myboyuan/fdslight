#!/usr/bin/env python3
"""端口映射的基本访问类
"""


class base(object):
    __map_info = None

    def __init__(self):
        self.__map_info = {}
        self.myinit()

    def myinit(self):
        """重写这个方法
        :return:
        """
        pass

    def handle_packet_from_recv(self, key, packet_size):
        """重写这个方法,处理从服务器tun设备接受过来的数据
        :param packet_size:
        :return Boolean: True表示接受数据包,False表示抛弃数据包
        """
        return True

    def handle_packet_for_send(self, key, packet_size):
        """重写这个方法,处理发送到服务器tun设备的数据
        :param packet_size:
        :return Boolean: True表示接受数据包,False表示抛弃数据包
        """
        return True

    def set_map_info(self, key: str, address: str, protocol: str, port: int, is_ipv6=False):
        pass

    def get_map_rule(self, byte_ip, proto_num, port):
        """获取映射规则
        :return:
        """
        pass

    def clear_map_rule(self):
        self.__map_info = {}

    def change_map_rule(self):
        """改变映射规则,重写这个方法,该函数用于程序不重新启动的情况下更改端口映射规则
        :return:
        """
        pass
