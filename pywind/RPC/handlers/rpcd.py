#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.RPC.lib.protocol as rpc_protocol

import time, socket


class rpcd_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, listen_address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)

        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(listen_address)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, rpc_handler, cs, address)
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class rpc_handler(tcp_handler.tcp_handler):
    # 用户保存的对象,用于对类实例,文件这些调用状态的保存
    __objects = None

    __LOOP_TIMEOUT = 60

    __update_time = None
    __conn_timeout = None

    __builder = None
    __parser = None

    def init_func(self, creator, cs, address, conn_timeout=600):
        self.__objects = {}
        self.__update_time = time.time()
        self.__conn_timeout = conn_timeout

        self.__parser = rpc_protocol.parser()

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return

    def set_object(self, obj_id, o, del_func):
        """设置对象
        :param obj_id: 对象ID
        :param o: 对象实例
        :param del_func:资源释放函数
        :return: 
        """
        self.__objects[obj_id] = (o, del_func,)

    def __del_objects(self):
        for k, v in self.__objects.items():
            _, del_func = v
            # 调用资源释放函数进行资源释放
            del_func()
        return

    def tcp_delete(self):
        self.__del_objects()
        self.unregister(self.fileno)
        self.close()

    def tcp_timeout(self):
        t = time.time()
        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_readable(self):
        rdata = self.reader.read()

        self.__parser.put_data(rdata)

        while 1:
            self.__parser.parse()
            rs = self.__parser.get_result()
            if not rs: break
            token_id, content = rs
            if not self.is_permit_access(token_id):
                self.delete_handler(self.fileno)
                return
            if not self.__builder:
                self.__builder = rpc_protocol.builder(token_id)

            b = self.__handle_function_call(content)
            if not b:
                self.delete_handler(self.fileno)
                return
        self.__update_time = time.time()

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def __handle_function_call(self, content):
        try:
            sts = content.decode()
        except UnicodeDecodeError:
            return False
        try:
            pydict = rpc_protocol.parse_function_call(sts)
        except rpc_protocol.ProtocolErr:
            return False

        call_id = pydict["call_id"]
        namespace = pydict["namespace"]
        func_name = pydict["function"]
        args = pydict["args"]
        kwargs = pydict["kwargs"]

        self.handle_function_call(
            call_id, namespace, func_name, *tuple(args), **kwargs
        )

        return True

    def get_object(self, obj_id):
        """获取对象
        :param obj_id: 
        :return: 
        """
        return self.__objects.get(obj_id, None)

    def del_object(self, obj_id):
        """删除对象
        注意:调用此函数不会自动调用资源释放函数
        :param obj_id: 
        :return: 
        """
        if obj_id not in self.__objects: return

        del self.__objects[obj_id]

    def object_exists(self, obj_id):
        """检查对象是否存在
        :param obj_id: 
        :return: 
        """
        return obj_id in self.__objects

    def is_permit_access(self, token_id):
        """重写这个方法,是否允许用户访问
        :param token_id: 
        :return Boolean: True表示允许访问,False表示禁止访问 
        """
        return True

    def handle_function_call(self, call_id, namespace, func_name, *args, **kwargs):
        """处理函数调用,重写这个方法
        :param call_id:
        :param namespace: 
        :param func_name: 
        :param args: 
        :param kwargs: 
        :return: 
        """
        pass

    def return_function_result(self, call_id, return_val=None, is_resource=False, is_err=None, err_code=None):
        """返回函数结果
        :param call_id: 
        :param return_val: 
        :param is_resource:
        :param is_err: 
        :param err_code: 
        :return: 
        """
        sts = rpc_protocol.build_function_return(
            call_id, return_val=return_val, is_class=is_resource,
            is_err=is_err, err_code=err_code
        )

        byte_data = sts.encode()

        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
