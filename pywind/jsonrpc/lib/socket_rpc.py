#!/usr/bin/env python3
### socket层上的RPC协议
"""协议如下
direction:1 byte , 0表示请求,1表示响应
is_first: 1 byte  , 0表示是第一次请求或者响应,1表示并非第一次请求或者响应
content_length:2 byte , 数据内容长度
"""
