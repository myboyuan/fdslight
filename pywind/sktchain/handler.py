#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.sktchain.node as skt_node


class _node(object):
    __nodes = None

    def __init__(self):
        self.__nodes = {}

    def create_node(self, node_name, node_cls_instance):
        self.__nodes[node_name] = node_cls_instance

    def node_exists(self, node_name):
        return self.node_exists(node_name)

    def del_node(self, node_name):
        if not self.node_exists(node_name): return

        del self.__nodes[node_name]

    def conn_node(self, node_name, side):
        if side not in (skt_node.SIDE_LEFT, skt_node.SIDE_RIGHT):
            return False

        if node_name not in self.__nodes: return False

        node = self.__nodes[node_name]

        if side == skt_node.SIDE_LEFT:
            return node.left

        return node.right

