#!/usr/bin/env python3
# 让你的局域网机器有公网IP地址,并对外提供服务


import sys, os

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile
import freenet.lib.utils as utils
import freenet.lib.base_proto.utils as proto_utils
import freenet.lib.proc as proc
import freenet.handlers.tunnelc as tunnelc
import os, signal, importlib, socket
import dns.resolver

PID_FILE = "/tmp/fdslight.pid"
LOG_FILE = "/tmp/fdslight.log"
ERR_FILE = "/tmp/fdslight_error.log"


class public_ip_serviced(dispatcher.dispatcher):
    __dev_fd = None
    __tunnel_fd = None

    __session_id = None

    def init_func(self, use_netmap=False):
        self.__dev_fd = -1
        self.__tunnel_fd = -1

        if use_netmap:
            self.create_poll(force_select=True)
            self.__create_netmap()
        else:
            self.create_poll()
            self.__create_tapdev()

    def __create_netmap(self):
        import freenet.handlers.netmap as nm

    def __create_tapdev(self):
        import freenet.handlers.tapdev as tapdev

    def __get_config(self):
        fpath = "%s/fdslight_etc/fn_public_ip_client.ini" % BASE_DIR
        configs = configfile.ini_parse_from_file(fpath)

        return configs

    def __create_tunnel(self):
        pass

    def __get_server_ip(self, host):
        """获取服务器IP
        :param host:
        :return:
        """
        if utils.is_ipv4_address(host): return host
        if utils.is_ipv6_address(host): return host

        enable_ipv6 = False
        # enable_ipv6 = bool(int(self.__configs["connection"]["enable_ipv6"]))
        resolver = dns.resolver.Resolver()
        # resolver.nameservers = [self.__configs["public"]["remote_dns"]]

        try:
            if enable_ipv6:
                rs = resolver.query(host, "AAAA")
            else:
                rs = resolver.query(host, "A")
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except dns.resolver.NoNameservers:
            return None

        for anwser in rs:
            ipaddr = anwser.__str__()
            break

        return ipaddr

    def handle_data_from_tap(self, message):
        if self.__tunnel_fd < 0:
            self.__create_tunnel()
        # 无法创建隧道那么直接丢弃数据包
        if self.__tunnel_fd < 0:
            return
        self.get_handler(self.__tunnel_fd).send_msg_to_tunnel(self.__session_id, proto_utils.ACT_LINK_DATA, message)

    def send_data_to_tunnel(self, action, message):
        pass


def __stop_service():
    pid = proc.get_pid(PID_FILE)
    if pid < 0: return

    os.kill(pid, signal.SIGINT)


def main():
    """
    :return:
    """
    # 是否使用netmap
    use_netmap = False


if __name__ == '__main__': main()
