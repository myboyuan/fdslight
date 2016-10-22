#!/usr/bin/env python3
"""进程之间的RPC通信"""
import pywind.evtframework.handler.tcp_handler as tcp_handler
import pywind.rpc.lib.rpc_func as rpc_func
import pywind.rpc.lib.proto as rpc_proto
import pywind.rpc.lib.jsonrpc as jsonrpc


class rpcd(tcp_handler.tcp_handler):
    __rpc_func = None
    __caddr = None
    __register_functions = None

    __proto_builder = None
    __proto_parser = None

    __js_builder = None
    __js_parser = None

    @property
    def caddr(self):
        return self.__caddr

    def __register_func(self, functions):
        if not self.__rpc_func: self.__rpc_func = rpc_func.func_call()
        for module in functions:
            for name, func in functions[module]: self.__rpc_func.register_function(name, func, module)
        return

    def init_func(self, creator_fd, register_functions, address=None, sock=None, caddr=None):
        if sock:
            self.set_socket(sock)

            self.__register_func(register_functions)
            self.__caddr = caddr

            self.__proto_builder = rpc_proto.builder()
            self.__proto_parser = rpc_proto.parser()

            self.__js_builder = jsonrpc.jsonrpc_builder(0)
            self.__js_parser = jsonrpc.jsonrpc_parser(0)

            self.register(self.fileno)
            self.add_evt_read(self.fileno)

            return self.fileno

        if isinstance(address, tuple):
            s = socket.socket()
        else:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__register_functions = register_functions
        self.set_socket(s)
        self.bind(address)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
                self.create_handler(self.fileno, rpcd, self.__register_functions, sock=cs, caddr=caddr)
            except BlockingIOError:
                break
        return

    def __handle_rpc(self, rpc_data):
        try:
            pydict = self.__js_parser.parse(rpc_data)
        except jsonrpc.jsonrpcErr:
            self.delete_handler(self.fileno)
            return
        method = pydict["method"]
        ok = True

        try:
            result = self.__rpc_func.call_func(method, pydict["params"])
        except rpc_func.RPCNotFoundMethodErr:
            pydict = self.__js_builder.build_return_error(
                jsonrpc.E_NOT_FOUND_METHOD, "cannot found method %s" % method)
            ok = False
        except rpc_func.RPCInvalidParamsErr:
            pydict = self.__js_builder.build_return_error(
                jsonrpc.E_INVALID_PARAMS, "invalid method params on function %s" % method
            )
            ok = False

        if ok: pydict = self.__js_builder.build_return_ok(result)

        resp_data = self.__proto_builder.build_response(json.dumps(pydict))

        self.add_evt_write(self.fileno)
        self.writer.write(resp_data)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        pass

    def tcp_readable(self):
        # 只支持同步调用
        rdata = self.reader.read()
        self.__proto_parser.input(rdata)
        self.__proto_parser.parse()
        rs = self.__proto_parser.get_result()

        if rs == None:
            self.reader._putvalue(rdata)
            return
        self.__handle_rpc(rs)

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.socket.close()


class rpcc(tcp_handler.tcp_handler):
    """客户端"""
    pass
