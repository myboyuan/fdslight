#!/usr/bin/env python3
import socket

import pywind.evtframework.consts as consts
import pywind.evtframework.excepts as excepts
import pywind.evtframework.handler.tcp_handler as tcp_handler
import pywind.web.hooks.http1x as http1x_hook
import pywind.web.lib.exceptions as web_excpts
from pywind.global_vars import global_vars


class web_handler(tcp_handler.tcp_handler):
    __config = None
    # 客户端地址
    __client_address = None

    def init_func(self, creator_fd, config, s=None, c_addr=None, ssl_on=False):
        """
        :param creator_fd:
        :param config:{
        "bind_address":(ipaddr,port),
        "ssl_on":True | False,
        "timeout":seconds,
        "bind_host":host,
        "ip_type":"ipv6" or "ipv4"
        }
        :param s:socket对象,如果这个参数不为空,表明是一个服务套接字
        :param c_addr:客户端地址
        :return:
        """
        self.__config = config

        if s:
            self.__client_address = c_addr
            self.set_socket(s)
            self.set_fileno(s.fileno())
            self.register(self.fileno)
            self.add_evt_read(self.fileno)

            self.__loop_functions_for_write = []
            self.activate_hook(http1x_hook.http1x_hook, config, ssl_on=ssl_on)

            return self.fileno

        addr_type = config.get("ip_type", "ipv4")

        if addr_type not in ["ipv4", "ipv6"]:
            raise web_excpts.ConfigError("the ip type wrong,the value is `ipv4` or `ipv6`")

        if addr_type == "ipv4":
            s = socket.socket()
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(config["http_bind"])

        self.set_fileno(s.fileno())
        self.set_socket(s)

        return self.fileno

    def after(self):
        self.listen(100)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        name_a = "max_conns"
        name_b = "pywind.webserver.current_conns"

        max_conns = self.__config[name_a]
        current_conns = global_vars[name_b]

        while 1:
            try:
                s, addr = self.socket.accept()
                if current_conns > max_conns:
                    s.close()
                    continue
                current_conns += 1
            except BlockingIOError:
                break
            except:
                break

            self.create_handler(self.fileno, web_handler, self.__config, s=s, c_addr=addr)
        global_vars[name_b] = current_conns

    def tcp_readable(self):
        if not self.hook_exists("input"):
            self.delete_handler(self.fileno)
            return

        rdata = self.reader.read()
        self.hook_input("input", rdata)

    def tcp_writable(self):
        if self.notify_exists(consts.NOTIFY_WRITE):
            boolean = self.execute_notify(consts.NOTIFY_WRITE)
            if boolean: return
            self.del_notify(consts.NOTIFY_WRITE)
        if self.writer.size() < 1:
            self.remove_evt_write(self.fileno)
            return
        return

    def hook_output(self, name, byte_data):
        if name == "output":
            self.writer.write(byte_data)
            self.add_evt_write(self.fileno)
            return

        if self.hook_exists(name):
            self.hook_input(name, byte_data)
            return

        raise excepts.HookNotExistsErr("can not found hook %s" % name)

    def tcp_timeout(self):
        pass

    def tcp_reset(self):
        pass

    def tcp_delete(self):
        pass

    def tcp_error(self):
        pass
