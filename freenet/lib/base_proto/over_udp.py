#!/usr/bin/env python3
"""基于UDP的IP加密协议
session_id: 2 bytes 会话id,由程序自动生成
data_id:2 bytes 当前数据id号
data_block_n:1 bytes 数据分成的总段数
data_block_seq:1 bytes 当前数据段序号
data_length: 2 bytes 数据长度

data area
"""


class over_udp_builder(object):
    pass


class over_udp_parser(object):
    pass
