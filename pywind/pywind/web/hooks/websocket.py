#!/usr/bin/env python3
import pywind.evtframework.handler.hhook.hook as hook
import pywind.web.lib.websocket as websocket


### wensocket的一些设置选项
# websocket数据分片
WS_OPT_DATA_SLICE = 0
# 设置数据分片大小
WS_OPT_SLICE_SIZE = 1
# 设置websocket rsv帧
WS_OPT_RSV = 2
# 设置websocket opcode
WS_OPT_OPCODE = 3

### 以下是一些选项的值
## 数据分片
# 数据不要分片
WS_VAL_NO_SLICE = 0
# 使用数据分片
WS_VAL_SLICE = 1
## opcode的值
# 表示是一个连续的帧
WS_VAL_OP_CT_FRAME = 0x0
# 表示这是一个文本帧
WS_VAL_OP_TEXT_FRAME = 0x1
# 表示这是一个二进制帧
WS_VAL_OP_BIN_FRAME = 0x2
# 表示连接关闭
WS_VAL_OP_CLOSE = 0x8
# 表示是一个ping帧
WS_VAL_OP_PING = 0x9
# 表示是一个pong帧
WS_VAL_OP_PONG = 0xa


class websocket_hook(hook.hook):
    __readable_list = None
    __encoder = None
    __decoder = None
    __opts = [
        WS_OPT_DATA_SLICE,
        WS_OPT_OPCODE,
        WS_OPT_RSV,
        WS_OPT_SLICE_SIZE
    ]
    # websocket支持的版本
    __SUPPORT_VERSION = 13
    # 是否已经响应了关闭帧
    __is_resp_close = False

    def hook_input(self, byte_data):
        pass

    def hook_ctl(self, cmd, *args, **kwargs):
        pass

    def hook_init(self, fd, *args, **kwargs):
        self.__readable_list = []
        self.__encoder = websocket.encoder()
        self.__decoder = websocket.decoder()

    def hook_delete(self):
        pass

    def ws_setoption(self, option, value):
        """设置websocket的一些参数
        :param option:
        :param value:
        :return:
        """
        pass

    def ws_getoption(self, option):
        """获取websocket的一些参数
        :param option:
        :return:
        """
        pass

    def ws_send(self, byte_data):
        """websocket数据写
        :param byte_data:
        :return:
        """
        pass

    def ws_recv(self, buf_size):
        """接收websocket数据
        :param buf_size:
        :return:
        """
        pass

    def ws_close(self):
        """关闭websocket
        :return:
        """
        pass

    def ws_readable(self):
        """websocket数据可读,重写这个方法
        :return:
        """
        pass
